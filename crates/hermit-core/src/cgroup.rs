//! Best-effort cgroup v2 placement.
//!
//! An unprivileged process can only create sub-cgroups inside a subtree that
//! was delegated to it (systemd `Delegate=yes`, or `user@.service`). We detect
//! our own cgroup from `/proc/self/cgroup`, try to create a sibling/child leaf
//! there, enable the controllers we need on the parent if the kernel lets us,
//! and move the sandbox PID-1 in. Anything that fails is reported as a reason
//! string in `Applied::cgroup` so every outcome states its real resource model.

use crate::Limits;
use nix::unistd::Pid;
use std::path::{Path, PathBuf};

const CG_ROOT: &str = "/sys/fs/cgroup";

fn own_cgroup() -> Option<PathBuf> {
    let s = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in s.lines() {
        // cgroup v2 unified: "0::/user.slice/user-1000.slice/session-3.scope"
        if let Some(rest) = line.strip_prefix("0::") {
            let rel = rest.trim_start_matches('/');
            return Some(Path::new(CG_ROOT).join(rel));
        }
    }
    None
}

/// Try to create a leaf cgroup for `pid`, apply limits, and move it there.
/// Returns the leaf path on success, or a reason why it was not possible.
pub fn place(pid: Pid, limits: &Limits) -> Result<String, String> {
    if std::env::var_os("SBX_NO_CGROUP").is_some() {
        return Err("disabled by SBX_NO_CGROUP".into());
    }
    if !Path::new(CG_ROOT).join("cgroup.controllers").exists() {
        return Err("cgroup v2 not mounted".into());
    }
    let own = own_cgroup().ok_or_else(|| "cannot determine own cgroup".to_string())?;

    // Walk up until we find a directory we can create children in.
    let mut parent = own.clone();
    let mut leaf: Option<PathBuf> = None;
    for _ in 0..6 {
        let candidate = parent.join(format!("sbx-{}", pid.as_raw()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                leaf = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // not delegated here; try the parent of the parent
                if let Some(p) = parent.parent() {
                    if p == Path::new(CG_ROOT) || p == Path::new("/sys/fs") {
                        break;
                    }
                    parent = p.to_path_buf();
                    continue;
                }
                break;
            }
            Err(e) => return Err(format!("mkdir {}: {e}", candidate.display())),
        }
    }
    let leaf = leaf.ok_or_else(|| {
        format!(
            "no writable (delegated) cgroup subtree above {}",
            own.display()
        )
    })?;

    // Enable controllers on the parent (may fail if the parent has processes — "no internal processes" rule).
    let mut ctrl_note = String::new();
    let _ = std::fs::write(parent.join("cgroup.subtree_control"), "+memory +pids")
        .map_err(|e| ctrl_note = format!(" (subtree_control: {e})"));

    let mut applied = Vec::new();
    if let Some(m) = limits.memory_bytes {
        if std::fs::write(leaf.join("memory.max"), m.to_string()).is_ok() {
            applied.push("memory.max");
            let _ = std::fs::write(leaf.join("memory.swap.max"), "0");
        }
    }
    if let Some(p) = limits.pids {
        if std::fs::write(leaf.join("pids.max"), p.to_string()).is_ok() {
            applied.push("pids.max");
        }
    }
    std::fs::write(leaf.join("cgroup.procs"), pid.as_raw().to_string()).map_err(|e| {
        let _ = std::fs::remove_dir(&leaf);
        format!("move pid into {}: {e}", leaf.display())
    })?;
    Ok(format!(
        "{} [{}]{}",
        leaf.display(),
        applied.join(","),
        ctrl_note
    ))
}

/// Remove the leaf after the sandbox exited (all processes are gone with PID-1).
pub fn cleanup(applied: &str) {
    if let Some(path) = applied.split(' ').next() {
        if path.starts_with(CG_ROOT) {
            // Processes may need a moment to be reaped from the cgroup.
            for _ in 0..50 {
                if std::fs::remove_dir(path).is_ok() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }
}
