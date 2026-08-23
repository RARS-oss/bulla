//! seccomp-bpf filter installed right before `execve`.
//!
//! Policy: a *denylist* with `EPERM` as the action, not an allowlist. Arbitrary
//! toolchains (gcc, python, cargo, node, JVM) use a long tail of syscalls; an
//! allowlist that breaks `cargo test` silently is worse than no filter. What we
//! deny is the set that matters for containment or determinism even inside a
//! user namespace:
//!
//! * kernel attack surface: `io_uring_*`, `bpf`, `perf_event_open`, `userfaultfd`,
//!   `keyctl`/`add_key`/`request_key`, `kexec_*`, `init_module`/`finit_module`/
//!   `delete_module`, `open_by_handle_at`, `fanotify_init`, `lookup_dcookie`,
//!   `quotactl`, `acct`, `reboot`, `swapon`/`swapoff`, `vhangup`, `ptrace`,
//!   `process_vm_readv`/`writev`, `kcmp`, `pidfd_getfd`;
//! * escaping the setup we just built: `unshare`, `setns`, `mount`, `umount2`,
//!   `pivot_root`, `move_mount`, `open_tree`, `fsopen`, `fsmount`, `fsconfig`,
//!   `fspick`, `mount_setattr`, `chroot`, `sethostname`, `setdomainname`,
//!   `personality` (ASLR state is fixed), `settimeofday`, `clock_settime`,
//!   `clock_adjtime`, `adjtimex`;
//! * `socket(AF_ALG, …)` (a large historical kernel-crypto attack surface) and
//!   other exotic families; `AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK` stay allowed.
//!
//! This is a **denylist** (default-allow): it reduces kernel attack surface and locks the
//! mount/namespace calls that would unpick the setup — it is a layer on top of the namespace +
//! uid-map boundary, not the boundary itself. The x32 ABI variants of every denied call are also
//! blocked (see `apply`). On a kernel without user namespaces or with `--no-seccomp`, that layer
//! is absent; see the threat-model note in the README.
//!
//! Denied calls return `EPERM` (not `SIGSYS`) so that probing code degrades
//! gracefully (`io_uring` users fall back to epoll, for instance).

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

#[cfg(target_arch = "x86_64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

fn denied_syscalls() -> Vec<i64> {
    let mut v: Vec<i64> = vec![
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_open_by_handle_at,
        libc::SYS_fanotify_init,
        libc::SYS_quotactl,
        libc::SYS_acct,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_vhangup,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_pidfd_getfd,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_chroot,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_personality,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        v.push(libc::SYS_kexec_file_load);
        v.push(libc::SYS_lookup_dcookie);
        v.push(libc::SYS_uselib);
        v.push(libc::SYS_ioperm);
        v.push(libc::SYS_iopl);
        v.push(libc::SYS_modify_ldt);
    }
    v
}

/// Build and install the filter. Must run after all mounts/rlimits and with
/// `PR_SET_NO_NEW_PRIVS` already set (unprivileged seccomp requires it).
pub fn apply() -> anyhow::Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // Also deny the x32 ABI variant (nr | 0x40000000): the same call through the x32 entry would
    // otherwise slip past a raw-number denylist. no_new_privs is set, so the filter is inherited.
    const X32: i64 = 0x4000_0000;
    for nr in denied_syscalls() {
        // Empty rule vector = match every invocation of this syscall.
        rules.insert(nr, vec![]);
        rules.insert(nr | X32, vec![]);
    }
    // socket(): deny everything except AF_UNIX(1), AF_INET(2), AF_INET6(10), AF_NETLINK(16).
    // Expressed as: match (= deny) when domain is one of the exotic families we care about.
    // A positive list is not expressible as "match" rules with a single action, so we
    // enumerate the families to block: AF_ALG (38), AF_PACKET (17), AF_VSOCK (40), AF_KEY (15),
    // AF_XDP (44), AF_BLUETOOTH (31), AF_CAN (29), AF_RDS (21), AF_TIPC (30), AF_IB (27),
    // AF_MPLS (28), AF_NFC (39), AF_KCM (41), AF_QIPCRTR (42), AF_SMC (43), AF_IUCV (32),
    // AF_RXRPC (33), AF_ISDN (34), AF_PHONET (35), AF_IEEE802154 (36), AF_CAIF (37),
    // AF_AX25 (3), AF_IPX (4), AF_APPLETALK (5), AF_NETROM (6), AF_BRIDGE (7), AF_ATMPVC (8),
    // AF_X25 (9), AF_ROSE (11), AF_DECnet (12), AF_NETBEUI (13), AF_SECURITY (14),
    // AF_ASH (18), AF_ECONET (19), AF_ATMSVC (20), AF_SNA (22), AF_IRDA (23), AF_PPPOX (24),
    // AF_WANPIPE (25), AF_LLC (26).
    let blocked_families: &[u64] = &[
        3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    ];
    let mut socket_rules = Vec::new();
    for fam in blocked_families {
        socket_rules.push(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            *fam,
        )?])?);
    }
    rules.insert(libc::SYS_socket, socket_rules);
    // x32 socket(): rebuild the same family-block rules for the x32 entry.
    let mut socket_rules_x32 = Vec::new();
    for fam in blocked_families {
        socket_rules_x32.push(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            *fam,
        )?])?);
    }
    rules.insert(libc::SYS_socket | X32, socket_rules_x32);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // mismatch: allow
        SeccompAction::Errno(libc::EPERM as u32), // match: EPERM
        ARCH,
    )?;
    let bpf: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&bpf)?;
    Ok(())
}
