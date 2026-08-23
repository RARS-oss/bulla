//! The child side of `run()`: everything that happens inside the new
//! namespaces before `execvpe`. Runs in a freshly cloned process, so it may
//! allocate freely, but it must never return into the parent's code paths —
//! it either execs or exits.

use crate::{Rootfs, Spec};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::resource::{setrlimit, Resource};
use nix::sys::statvfs::{statvfs, FsFlags};
use nix::unistd::{chdir, pivot_root, sethostname};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

pub(crate) struct ChildCfg {
    pub spec: Spec,
    pub new_root: PathBuf,
    pub stdout_fd: RawFd,
    pub stderr_fd: RawFd,
    pub stdin_fd: RawFd,
    pub sync_fd: RawFd,
    pub ready_fd: RawFd,
}

fn report(fd: RawFd, msg: &str) {
    let b = msg.as_bytes();
    unsafe {
        libc::write(fd, b.as_ptr() as *const libc::c_void, b.len());
    }
}

/// Entry point of the cloned child. Returns the exit code if exec fails.
pub(crate) fn child_main(cfg: &ChildCfg) -> isize {
    // Wire stdio first so any error text is captured by the parent.
    unsafe {
        libc::dup2(cfg.stdin_fd, 0);
        libc::dup2(cfg.stdout_fd, 1);
        libc::dup2(cfg.stderr_fd, 2);
    }
    // Wait until the parent has written uid/gid maps (and placed us in a cgroup).
    {
        let mut b = [0u8; 2];
        unsafe {
            libc::read(cfg.sync_fd, b.as_mut_ptr() as *mut libc::c_void, 2);
            libc::close(cfg.sync_fd);
        }
    }
    match setup_and_exec(cfg) {
        Ok(never) => match never {},
        Err(e) => {
            report(cfg.ready_fd, &format!("err {e}"));
            eprintln!("sbx: setup failed: {e}");
            127
        }
    }
}

fn setup_and_exec(cfg: &ChildCfg) -> anyhow::Result<std::convert::Infallible> {
    let spec = &cfg.spec;
    let mut applied: Vec<&'static str> = Vec::new();

    // --- UTS ---
    let _ = sethostname(&spec.hermetic.hostname);

    // --- Loopback up (new netns has lo DOWN) ---
    if spec.hermetic.no_network && spec.hermetic.loopback && crate::netlink::loopback_up().is_ok() {
        applied.push("loopback");
    }

    // --- Mounts ---
    // Make every mount private so nothing we do propagates back to the host.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| anyhow::anyhow!("make / private: {e}"))?;

    let root = &cfg.new_root;
    // tmpfs as the new root.
    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=755,size=64m"),
    )
    .map_err(|e| anyhow::anyhow!("mount tmpfs root at {}: {e}", root.display()))?;

    // System directories.
    match &spec.rootfs {
        Rootfs::HostReadOnly => {
            for p in crate::host_system_dirs() {
                if !p.exists() {
                    continue;
                }
                mirror_ro(p, root)?;
            }
        }
        Rootfs::Dir(dir) => {
            for entry in std::fs::read_dir(dir)
                .map_err(|e| anyhow::anyhow!("read rootfs dir {}: {e}", dir.display()))?
            {
                let entry = entry?;
                let name = entry.file_name();
                let name_s = name.to_string_lossy();
                if matches!(
                    name_s.as_ref(),
                    "proc" | "sys" | "dev" | "tmp" | "run" | "work"
                ) {
                    continue;
                }
                mirror_ro_as(&entry.path(), &root.join(&name))?;
            }
        }
    }

    // Extra binds.
    for p in &spec.ro_binds {
        if p.exists() {
            bind(p, &root.join(rel(p)), true)?;
        }
    }
    for p in &spec.rw_binds {
        if p.exists() {
            bind(p, &root.join(rel(p)), false)?;
        }
    }

    // /work: either an overlay (read-only lower repo + work_dir as the writable upper, so a large
    // repo is not copied) or a plain read-write bind of the work dir.
    std::fs::create_dir_all(root.join("work"))?;
    if let Some(lower) = &spec.overlay_lower {
        let upper = spec.work_dir.join("upper");
        let ovwork = spec.work_dir.join(".ovwork");
        std::fs::create_dir_all(&upper)?;
        std::fs::create_dir_all(&ovwork)?;
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            ovwork.display()
        );
        mount(
            Some("overlay"),
            &root.join("work"),
            Some("overlay"),
            MsFlags::empty(),
            Some(opts.as_str()),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "mount overlay /work (lower={}, upper={}): {e} — work_dir must be on a Linux fs that supports overlayfs",
                lower.display(),
                upper.display()
            )
        })?;
    } else {
        bind(&spec.work_dir, &root.join("work"), false)?;
    }
    std::fs::create_dir_all(root.join("tmp"))?;
    mount(
        Some("tmpfs"),
        &root.join("tmp"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=1g"),
    )
    .map_err(|e| anyhow::anyhow!("mount /tmp: {e}"))?;
    std::fs::create_dir_all(root.join("run"))?;
    setup_dev(root)?;
    std::fs::create_dir_all(root.join("proc"))?;
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| anyhow::anyhow!("mount /proc: {e}"))?;
    // Read-only sysfs (permitted because we own the network namespace). Best-effort:
    // some tools (nproc, python's os.cpu_count, numpy) read /sys.
    std::fs::create_dir_all(root.join("sys"))?;
    let _ = mount(
        Some("sysfs"),
        &root.join("sys"),
        Some("sysfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );
    // Mask a few kernel interfaces that leak host state or are dangerous.
    for m in [
        "proc/kcore",
        "proc/sysrq-trigger",
        "proc/timer_list",
        "proc/sched_debug",
        "proc/kallsyms",
    ] {
        let t = root.join(m);
        if t.exists() {
            let _ = mount(
                Some("/dev/null"),
                &t,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
    }

    // pivot_root.
    let old = root.join(".oldroot");
    std::fs::create_dir_all(&old)?;
    pivot_root(root, &old).map_err(|e| anyhow::anyhow!("pivot_root: {e}"))?;
    chdir("/")?;
    umount2("/.oldroot", MntFlags::MNT_DETACH)
        .map_err(|e| anyhow::anyhow!("detach old root: {e}"))?;
    let _ = std::fs::remove_dir("/.oldroot");
    applied.push("pivot_root");
    // The tmpfs root itself becomes read-only; /work, /tmp, /dev/shm stay writable as their own
    // mounts. Keeps stray writes (and "escape" probes) out of the root directory.
    let _ = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    );

    // --- Hermetic profile ---
    if spec.hermetic.no_aslr {
        let r = unsafe { libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong) };
        if r != -1 {
            applied.push("no_aslr");
        }
    }
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r == 0 {
        applied.push("no_new_privs");
    }

    // --- rlimits ---
    let l = &spec.limits;
    let mut rl = |res: Resource, v: Option<u64>, name: &'static str| {
        if let Some(v) = v {
            if setrlimit(res, v, v).is_ok() {
                applied.push(name);
            }
        }
    };
    rl(Resource::RLIMIT_CPU, l.cpu_seconds, "rlimit:cpu");
    rl(Resource::RLIMIT_AS, l.address_space_bytes, "rlimit:as");
    rl(Resource::RLIMIT_NOFILE, l.nofile, "rlimit:nofile");
    rl(Resource::RLIMIT_FSIZE, l.fsize_bytes, "rlimit:fsize");
    rl(
        Resource::RLIMIT_NPROC,
        l.pids.map(|p| p as u64),
        "rlimit:nproc",
    );
    // No core dumps by default: they are slow, huge, and non-deterministic in size.
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);

    // --- Environment ---
    let mut env: Vec<(String, String)> = Vec::new();
    if spec.hermetic.fixed_env {
        env.extend(
            [
                ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                ("HOME", "/work"),
                ("USER", "sbx"),
                ("LOGNAME", "sbx"),
                ("SHELL", "/bin/sh"),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("TZ", "UTC"),
                ("TERM", "dumb"),
                ("NO_COLOR", "1"),
                ("PYTHONHASHSEED", "0"),
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("CARGO_TERM_COLOR", "never"),
                ("RUST_BACKTRACE", "1"),
                ("ASAN_OPTIONS", "symbolize=1:detect_leaks=0:abort_on_error=0:halt_on_error=1:print_stacktrace=1"),
                ("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1"),
                ("TMPDIR", "/tmp"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        env.push((
            "SOURCE_DATE_EPOCH".into(),
            spec.hermetic.source_date_epoch.to_string(),
        ));
        env.push(("SBX_SEED".into(), spec.hermetic.seed.to_string()));
        env.push(("SBX".into(), "1".into()));
        applied.push("fixed_env");
    } else {
        env.extend(std::env::vars());
    }
    for (k, v) in &spec.env {
        env.retain(|(ek, _)| ek != k);
        env.push((k.clone(), v.clone()));
    }

    chdir("/work")?;

    // --- seccomp (last: nothing after this may mount/unshare/ptrace) ---
    if spec.hermetic.seccomp {
        match crate::seccomp::apply() {
            Ok(()) => applied.push("seccomp"),
            Err(e) => {
                // Refusing to run is safer than running unfiltered when the caller asked for it.
                return Err(anyhow::anyhow!("seccomp: {e}"));
            }
        }
    }

    // Tell the parent we are about to exec (and what got applied).
    report(cfg.ready_fd, &format!("ok {}", applied.join(" ")));
    unsafe {
        libc::close(cfg.ready_fd);
    }

    // --- exec ---
    let argv: Vec<CString> = spec
        .argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_default())
        .collect();
    let envp: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap_or_default())
        .collect();
    // execvpe resolves PATH from the *new* environment (we pass it explicitly).
    let path_var = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let prog = resolve(&spec.argv[0], &path_var);
    let prog_c = CString::new(prog.as_str()).unwrap_or_default();
    let e = nix::unistd::execve(&prog_c, &argv, &envp).unwrap_err();
    Err(anyhow::anyhow!("exec {}: {e}", prog))
}

fn rel(p: &Path) -> PathBuf {
    p.strip_prefix("/")
        .map(|r| r.to_path_buf())
        .unwrap_or_else(|_| p.to_path_buf())
}

fn resolve(prog: &str, path_var: &str) -> String {
    if prog.contains('/') {
        return prog.to_string();
    }
    for dir in path_var.split(':') {
        let cand = Path::new(dir).join(prog);
        if cand.is_file() {
            return cand.to_string_lossy().into_owned();
        }
    }
    prog.to_string()
}

/// Mirror a host system dir into the new root at the same name: symlinks are
/// re-created as symlinks (Ubuntu's /bin -> usr/bin), directories are bound read-only.
fn mirror_ro(host: &Path, root: &Path) -> anyhow::Result<()> {
    mirror_ro_as(host, &root.join(rel(host)))
}

fn mirror_ro_as(host: &Path, target: &Path) -> anyhow::Result<()> {
    let md = std::fs::symlink_metadata(host)?;
    if md.file_type().is_symlink() {
        let link = std::fs::read_link(host)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(&link, target)?;
        return Ok(());
    }
    if md.is_dir() {
        bind(host, target, true)
    } else {
        // Regular file: bind-mount onto an empty file.
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::File::create(target)?;
        bind(host, target, true)
    }
}

/// Bind-mount `src` at `dst` (created if needed). Read-only binds are remounted
/// with the source's existing lock flags preserved — in a user namespace a remount
/// that drops nosuid/nodev/noexec/atime flags fails with EPERM.
fn bind(src: &Path, dst: &Path, readonly: bool) -> anyhow::Result<()> {
    let md = std::fs::metadata(src).map_err(|e| anyhow::anyhow!("stat {}: {e}", src.display()))?;
    if md.is_dir() {
        std::fs::create_dir_all(dst)?;
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !dst.exists() {
            std::fs::File::create(dst)?;
        }
    }
    mount(
        Some(src),
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| anyhow::anyhow!("bind {} -> {}: {e}", src.display(), dst.display()))?;
    if readonly {
        let st = statvfs(dst).map_err(|e| anyhow::anyhow!("statvfs {}: {e}", dst.display()))?;
        let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
        let f = st.flags();
        if f.contains(FsFlags::ST_NOSUID) {
            flags |= MsFlags::MS_NOSUID;
        }
        if f.contains(FsFlags::ST_NODEV) {
            flags |= MsFlags::MS_NODEV;
        }
        if f.contains(FsFlags::ST_NOEXEC) {
            flags |= MsFlags::MS_NOEXEC;
        }
        if f.contains(FsFlags::ST_NOATIME) {
            flags |= MsFlags::MS_NOATIME;
        }
        if f.contains(FsFlags::ST_NODIRATIME) {
            flags |= MsFlags::MS_NODIRATIME;
        }
        if f.contains(FsFlags::ST_RELATIME) {
            flags |= MsFlags::MS_RELATIME;
        }
        mount(None::<&str>, dst, None::<&str>, flags, None::<&str>)
            .map_err(|e| anyhow::anyhow!("remount ro {}: {e}", dst.display()))?;
    }
    Ok(())
}

/// Minimal /dev: tmpfs with the standard character devices bound from the host
/// (mknod is not permitted in a user namespace), /dev/shm, and the fd symlinks.
fn setup_dev(root: &Path) -> anyhow::Result<()> {
    let dev = root.join("dev");
    std::fs::create_dir_all(&dev)?;
    mount(
        Some("tmpfs"),
        &dev,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=16m"),
    )
    .map_err(|e| anyhow::anyhow!("mount /dev tmpfs: {e}"))?;
    for name in ["null", "zero", "full", "random", "urandom", "tty"] {
        let host = Path::new("/dev").join(name);
        if !host.exists() {
            continue;
        }
        let t = dev.join(name);
        std::fs::File::create(&t)?;
        mount(
            Some(&host),
            &t,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| anyhow::anyhow!("bind /dev/{name}: {e}"))?;
    }
    let shm = dev.join("shm");
    std::fs::create_dir_all(&shm)?;
    let _ = mount(
        Some("tmpfs"),
        &shm,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=256m"),
    );
    std::fs::create_dir_all(dev.join("pts"))?;
    let _ = mount(
        Some("devpts"),
        &dev.join("pts"),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    );
    std::os::unix::fs::symlink("/proc/self/fd", dev.join("fd"))?;
    std::os::unix::fs::symlink("/proc/self/fd/0", dev.join("stdin"))?;
    std::os::unix::fs::symlink("/proc/self/fd/1", dev.join("stdout"))?;
    std::os::unix::fs::symlink("/proc/self/fd/2", dev.join("stderr"))?;
    let _ = std::os::unix::fs::symlink("pts/ptmx", dev.join("ptmx"));
    Ok(())
}
