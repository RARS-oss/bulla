//! hermit-core — a small, dependency-light hermetic sandbox for running one
//! command under Linux namespaces with a deterministic environment profile.
//!
//! **Vendored** — this crate is reused verbatim from the sibling project
//! [RARS-oss/sbx](https://github.com/RARS-oss/sbx) (same author, MIT). It is the isolation
//! *mechanism* bulla builds on; the intent is to depend on a single published `hermit-core`
//! crate once sbx releases, rather than keep two copies in step by hand.
//!
//! Design (policy/mechanism split):
//! * [`Spec`] is pure data describing *what* to run and under which limits.
//! * [`run`] is the mechanism: clone(2) into fresh user/pid/mount/net/uts/ipc
//!   namespaces, build a private root (tmpfs + read-only host binds + fresh
//!   /proc + minimal /dev + rw work dir), `pivot_root`, apply rlimits and the
//!   hermetic profile, exec, and collect an [`Outcome`] (exit kind, rusage,
//!   captured streams, wall time, which isolation features were actually
//!   applied — so every run is self-describing).
//!
//! No root required: everything works from an unprivileged user namespace
//! (verified on WSL2 6.6 and stock Ubuntu kernels). cgroup v2 limits are
//! best-effort: applied when a delegated cgroup is available, otherwise the
//! outcome says so and rlimits carry the load.

pub mod cgroup;
mod child;
pub mod netlink;
pub mod seccomp;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sched::CloneFlags;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// Where the sandbox root comes from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Rootfs {
    /// Bind the host's system directories (/usr, /bin, /lib, /lib64, /sbin, /etc, /opt)
    /// read-only into a fresh tmpfs root. Fast, zero setup, good enough for
    /// compilers/interpreters already installed on the host.
    HostReadOnly,
    /// Use an extracted rootfs directory (bound read-only) — for pinned toolchains.
    Dir(PathBuf),
}

/// Resource limits. `None` = unlimited for that dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Wall-clock timeout. On expiry the PID-1 of the sandbox is SIGKILLed,
    /// which takes the whole pid namespace with it.
    pub wall: Duration,
    /// CPU seconds (RLIMIT_CPU, soft = hard).
    pub cpu_seconds: Option<u64>,
    /// Virtual address-space cap (RLIMIT_AS). OFF by default: AddressSanitizer
    /// reserves ~20 TB of VA and dies under RLIMIT_AS. Prefer cgroup memory.
    pub address_space_bytes: Option<u64>,
    /// cgroup v2 memory.max (best-effort).
    pub memory_bytes: Option<u64>,
    /// Max processes/threads: cgroup pids.max (best-effort) and RLIMIT_NPROC.
    pub pids: Option<u32>,
    /// Max open files (RLIMIT_NOFILE).
    pub nofile: Option<u64>,
    /// Max file size a process may create (RLIMIT_FSIZE).
    pub fsize_bytes: Option<u64>,
    /// Cap on captured stdout/stderr bytes each (the rest is discarded and flagged).
    pub capture_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            wall: Duration::from_secs(60),
            cpu_seconds: Some(60),
            address_space_bytes: None,
            memory_bytes: Some(2 * 1024 * 1024 * 1024),
            pids: Some(256),
            nofile: Some(1024),
            fsize_bytes: Some(256 * 1024 * 1024),
            capture_bytes: 8 * 1024 * 1024,
        }
    }
}

/// The deterministic-environment knobs ("hermetic profile").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hermetic {
    /// Replace the inherited environment with a fixed, minimal one
    /// (PATH, HOME, LANG/LC_ALL=C.UTF-8, TZ=UTC, SOURCE_DATE_EPOCH,
    /// PYTHONHASHSEED=0, TERM=dumb, ...). Extra vars from `Spec::env` are layered on top.
    pub fixed_env: bool,
    /// `personality(ADDR_NO_RANDOMIZE)`: stable addresses in backtraces / sanitizer reports.
    pub no_aslr: bool,
    /// Fixed hostname inside the UTS namespace.
    pub hostname: String,
    /// Value for SOURCE_DATE_EPOCH (seconds).
    pub source_date_epoch: u64,
    /// Disable network (new, empty net namespace with only a down loopback).
    pub no_network: bool,
    /// Seed exposed to the guest as SBX_SEED for programs that honour it.
    pub seed: u64,
    /// Install the seccomp-bpf denylist (io_uring, bpf, ptrace, mount/unshare/setns,
    /// keyctl, perf_event_open, userfaultfd, AF_ALG sockets, ...) right before exec.
    pub seccomp: bool,
    /// Bring `lo` UP inside the new network namespace (127.0.0.1 works, outside does not).
    pub loopback: bool,
}

impl Default for Hermetic {
    fn default() -> Self {
        Self {
            fixed_env: true,
            no_aslr: true,
            hostname: "sbx".to_string(),
            source_date_epoch: 1_700_000_000,
            no_network: true,
            seed: 0,
            seccomp: true,
            loopback: true,
        }
    }
}

/// Everything needed to run one command. Pure data; serialisable, so a run is
/// reproducible from its spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    pub argv: Vec<String>,
    /// Host directory bound read-write at `/work` inside the sandbox; also the cwd.
    pub work_dir: PathBuf,
    /// Extra host paths to bind read-only at the same path inside (e.g. a toolchain, a cache).
    pub ro_binds: Vec<PathBuf>,
    /// Extra host paths to bind read-write at the same path inside (e.g. a cargo registry cache).
    pub rw_binds: Vec<PathBuf>,
    pub rootfs: Rootfs,
    /// Extra environment variables (layered over the hermetic env, or the inherited one).
    pub env: BTreeMap<String, String>,
    pub limits: Limits,
    pub hermetic: Hermetic,
    /// Bytes written to the child's stdin (then EOF). Empty = /dev/null-like.
    pub stdin: Vec<u8>,
    /// If set, mount `/work` as an overlay of this read-only lower dir (e.g. a large repo, mounted
    /// without copying) with `work_dir` as the writable upper — the agent's edits land in
    /// `work_dir/upper`, the lower is never touched. `work_dir` must be on a Linux filesystem that
    /// supports overlayfs (not a `/mnt/c` drvfs mount).
    pub overlay_lower: Option<PathBuf>,
}

impl Spec {
    pub fn new<S: Into<String>>(argv: Vec<S>, work_dir: impl Into<PathBuf>) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            work_dir: work_dir.into(),
            ro_binds: vec![],
            rw_binds: vec![],
            rootfs: Rootfs::HostReadOnly,
            env: BTreeMap::new(),
            limits: Limits::default(),
            hermetic: Hermetic::default(),
            stdin: vec![],
            overlay_lower: None,
        }
    }
}

/// How the sandboxed process ended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitKind {
    Code {
        code: i32,
    },
    Signal {
        signal: i32,
        name: String,
        core_dumped: bool,
    },
    Timeout {
        after_ms: u64,
    },
    /// The sandbox itself failed before exec (mount error, missing binary...).
    SetupFailed {
        message: String,
    },
}

/// What actually got applied — every outcome carries its own provenance so
/// that experiments can be filtered by isolation level after the fact.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Applied {
    pub user_ns: bool,
    pub pid_ns: bool,
    pub mount_ns: bool,
    pub net_ns: bool,
    pub uts_ns: bool,
    pub ipc_ns: bool,
    pub cgroup_ns: bool,
    pub pivot_root: bool,
    pub no_new_privs: bool,
    pub no_aslr: bool,
    pub fixed_env: bool,
    /// seccomp-bpf denylist installed before exec.
    pub seccomp: bool,
    /// `lo` brought UP inside the network namespace.
    pub loopback: bool,
    /// "leaf path" when a cgroup was created, or a human-readable reason why not.
    pub cgroup: String,
    pub rlimits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Rusage {
    pub user_ms: u64,
    pub sys_ms: u64,
    pub max_rss_kb: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub vol_ctx_switches: u64,
    pub invol_ctx_switches: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub exit: ExitKind,
    pub wall_ms: u64,
    pub rusage: Rusage,
    #[serde(with = "bytes_as_lossy_string")]
    pub stdout: Vec<u8>,
    #[serde(with = "bytes_as_lossy_string")]
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub applied: Applied,
    /// Startup overhead: from `run()` entry to the moment the child reported "about to exec".
    pub setup_ms: u64,
}

impl Outcome {
    pub fn success(&self) -> bool {
        matches!(self.exit, ExitKind::Code { code: 0 })
    }
}

mod bytes_as_lossy_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&String::from_utf8_lossy(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        Ok(s.into_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("work_dir does not exist or is not a directory: {0}")]
    BadWorkDir(PathBuf),
    #[error("empty argv")]
    EmptyArgv,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Run one command in a fresh sandbox and wait for it.
pub fn run(spec: &Spec) -> Result<Outcome> {
    if spec.argv.is_empty() {
        return Err(Error::EmptyArgv);
    }
    if !spec.work_dir.is_dir() {
        return Err(Error::BadWorkDir(spec.work_dir.clone()));
    }
    let t0 = Instant::now();

    // Scratch directory that will become the new root (parent owns its lifetime).
    let scratch = Scratch::new()?;

    // Pipes: stdout, stderr, stdin, sync (parent -> child "maps written"),
    // ready (child -> parent "about to exec" / setup error).
    let (out_r, out_w) = nix::unistd::pipe()?;
    let (err_r, err_w) = nix::unistd::pipe()?;
    let (in_r, in_w) = nix::unistd::pipe()?;
    let (sync_r, sync_w) = nix::unistd::pipe()?;
    let (ready_r, ready_w) = nix::unistd::pipe()?;

    let cfg = child::ChildCfg {
        spec: spec.clone(),
        new_root: scratch.path.clone(),
        stdout_fd: out_w.as_raw_fd(),
        stderr_fd: err_w.as_raw_fd(),
        stdin_fd: in_r.as_raw_fd(),
        sync_fd: sync_r.as_raw_fd(),
        ready_fd: ready_w.as_raw_fd(),
    };

    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWCGROUP;
    if spec.hermetic.no_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    // 1 MiB stack for the child closure; the child execs almost immediately.
    let mut stack = vec![0u8; 1 << 20];
    let cb: nix::sched::CloneCb = Box::new(|| child::child_main(&cfg));
    // SAFETY: the child runs after a fork-like clone WITHOUT CLONE_VM, so until it execs it may
    // touch only its own data (`cfg`) and raw fds — no locks a parent thread could hold. This
    // requires `run()` to be called before the caller spawns threads: the reader threads below are
    // created *after* the clone, and the CLI is single-threaded. A multithreaded caller risks an
    // async-signal-unsafe-after-fork deadlock in the child's allocations — call `run()` first.
    let pid = unsafe { nix::sched::clone(cb, &mut stack, flags, Some(libc::SIGCHLD)) }?;

    // Parent side: close child ends, write id maps, release the child.
    drop(out_w);
    drop(err_w);
    drop(in_r);
    drop(sync_r);
    drop(ready_w);

    let mut applied = Applied {
        user_ns: true,
        pid_ns: true,
        mount_ns: true,
        net_ns: spec.hermetic.no_network,
        uts_ns: true,
        ipc_ns: true,
        cgroup_ns: true,
        ..Default::default()
    };

    write_id_maps(pid)?;
    applied.cgroup = match cgroup::place(pid, &spec.limits) {
        Ok(path) => path,
        Err(reason) => format!("unavailable: {reason}"),
    };
    // Release the child.
    {
        let mut f = std::fs::File::from(sync_w);
        let _ = f.write_all(b"go");
    }

    // Feed stdin then EOF.
    {
        let mut f = std::fs::File::from(in_w);
        if !spec.stdin.is_empty() {
            let _ = f.write_all(&spec.stdin);
        }
    }

    // Capture streams on threads.
    let cap = spec.limits.capture_bytes;
    let out_t = spawn_reader(out_r, cap);
    let err_t = spawn_reader(err_r, cap);

    // Wait for "ready" (child about to exec) or an error report; measures setup cost.
    let (ready_msg, setup_ms) = {
        let mut f = std::fs::File::from(ready_r);
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        (
            String::from_utf8_lossy(&buf).to_string(),
            t0.elapsed().as_millis() as u64,
        )
    };

    // Wait with timeout.
    let deadline = t0 + spec.limits.wall;
    let mut status: libc::c_int = 0;
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let mut timed_out = false;
    loop {
        let r = unsafe { libc::wait4(pid.as_raw(), &mut status, libc::WNOHANG, &mut ru) };
        if r == pid.as_raw() {
            break;
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Error::Io(e));
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = kill(pid, Signal::SIGKILL);
            // Reap synchronously.
            let _ = unsafe { libc::wait4(pid.as_raw(), &mut status, 0, &mut ru) };
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let wall_ms = t0.elapsed().as_millis() as u64;

    let (stdout, stdout_truncated) = out_t.join().unwrap_or((Vec::new(), false));
    let (stderr, stderr_truncated) = err_t.join().unwrap_or((Vec::new(), false));

    // Decode the child's ready message: "ok <flags>" or "err <message>".
    let exit = if timed_out {
        ExitKind::Timeout { after_ms: wall_ms }
    } else if let Some(msg) = ready_msg.strip_prefix("err ") {
        ExitKind::SetupFailed {
            message: msg.trim().to_string(),
        }
    } else if libc::WIFEXITED(status) {
        ExitKind::Code {
            code: libc::WEXITSTATUS(status),
        }
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        ExitKind::Signal {
            signal: sig,
            name: Signal::try_from(sig)
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|_| format!("SIG{sig}")),
            core_dumped: libc::WCOREDUMP(status),
        }
    } else {
        ExitKind::SetupFailed {
            message: format!("unexpected wait status {status}"),
        }
    };

    if let Some(rest) = ready_msg.strip_prefix("ok ") {
        for tok in rest.split_whitespace() {
            match tok {
                "pivot_root" => applied.pivot_root = true,
                "no_new_privs" => applied.no_new_privs = true,
                "no_aslr" => applied.no_aslr = true,
                "fixed_env" => applied.fixed_env = true,
                "seccomp" => applied.seccomp = true,
                "loopback" => applied.loopback = true,
                t if t.starts_with("rlimit:") => applied.rlimits.push(t[7..].to_string()),
                _ => {}
            }
        }
    }

    let rusage = Rusage {
        user_ms: tv_ms(ru.ru_utime),
        sys_ms: tv_ms(ru.ru_stime),
        max_rss_kb: ru.ru_maxrss as u64,
        minor_faults: ru.ru_minflt as u64,
        major_faults: ru.ru_majflt as u64,
        vol_ctx_switches: ru.ru_nvcsw as u64,
        invol_ctx_switches: ru.ru_nivcsw as u64,
    };

    cgroup::cleanup(&applied.cgroup);
    drop(scratch);

    Ok(Outcome {
        exit,
        wall_ms,
        rusage,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        applied,
        setup_ms,
    })
}

fn tv_ms(tv: libc::timeval) -> u64 {
    (tv.tv_sec as u64) * 1000 + (tv.tv_usec as u64) / 1000
}

/// Run `spec.argv` DIRECTLY, with no sandbox — for restricted containers where unprivileged user
/// namespaces are blocked (e.g. many rented GPU pods / CI runners). Captures stdout/stderr with a
/// wall-clock timeout and applies the fixed-env profile if requested; everything the verdict layer
/// needs is produced. `applied` reports all-false so results stay honestly labelled as un-isolated.
pub fn run_direct(spec: &Spec) -> Result<Outcome> {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    if spec.argv.is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty argv",
        )));
    }
    let cap = spec.limits.capture_bytes;
    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..])
        .current_dir(&spec.work_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if spec.hermetic.fixed_env {
        cmd.env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", &spec.work_dir)
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("TZ", "UTC")
            .env("TERM", "dumb")
            .env("PYTHONHASHSEED", "0")
            .env(
                "SOURCE_DATE_EPOCH",
                spec.hermetic.source_date_epoch.to_string(),
            );
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    let t0 = Instant::now();
    let mut child = cmd.spawn().map_err(Error::Io)?;
    match child.stdin.take() {
        Some(mut si) if !spec.stdin.is_empty() => {
            let _ = si.write_all(&spec.stdin);
        }
        _ => {}
    }
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let ot = std::thread::spawn(move || read_capped(&mut so, cap));
    let et = std::thread::spawn(move || read_capped(&mut se, cap));

    let deadline = t0 + spec.limits.wall;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(e) => return Err(Error::Io(e)),
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let wall_ms = t0.elapsed().as_millis() as u64;
    let (stdout, stdout_truncated) = ot.join().unwrap_or((Vec::new(), false));
    let (stderr, stderr_truncated) = et.join().unwrap_or((Vec::new(), false));

    let exit = if timed_out {
        ExitKind::Timeout { after_ms: wall_ms }
    } else {
        let st = status.expect("status present when not timed out");
        if let Some(code) = st.code() {
            ExitKind::Code { code }
        } else {
            let sig = st.signal().unwrap_or(0);
            ExitKind::Signal {
                signal: sig,
                name: Signal::try_from(sig)
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|_| format!("SIG{sig}")),
                core_dumped: st.core_dumped(),
            }
        }
    };

    Ok(Outcome {
        exit,
        wall_ms,
        rusage: Rusage::default(),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        applied: Applied {
            cgroup: "n/a (--no-sandbox: ran directly, nothing isolated)".into(),
            ..Default::default()
        },
        setup_ms: 0,
    })
}

fn read_capped<R: std::io::Read>(r: &mut R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (buf, truncated)
}

fn spawn_reader(fd: OwnedFd, cap: usize) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        // SAFETY: we own the fd; File takes ownership.
        let mut f = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        std::mem::forget(fd);
        let mut out = Vec::with_capacity(64 * 1024);
        let mut buf = [0u8; 64 * 1024];
        let mut truncated = false;
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len() < cap {
                        let take = n.min(cap - out.len());
                        out.extend_from_slice(&buf[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        (out, truncated)
    })
}

fn write_id_maps(pid: Pid) -> Result<()> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let base = format!("/proc/{}", pid.as_raw());
    std::fs::write(format!("{base}/uid_map"), format!("0 {uid} 1\n"))?;
    // setgroups must be denied before an unprivileged gid_map write.
    let _ = std::fs::write(format!("{base}/setgroups"), "deny\n");
    std::fs::write(format!("{base}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}

/// Owned scratch directory for the new root; removed on drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Result<Self> {
        let base = std::env::var_os("SBX_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = base.join(format!(".sbx-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Inside the child's mount namespace this was a mount point; on the host it is
        // just an empty directory. Best effort.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Convenience: the list of host system directories bound read-only for [`Rootfs::HostReadOnly`].
pub fn host_system_dirs() -> Vec<&'static Path> {
    [
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32", "/etc", "/opt",
    ]
    .iter()
    .map(Path::new)
    .collect()
}
