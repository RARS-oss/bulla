# hermit-core

The hermetic execution core behind [sbx](https://github.com/RARS-oss/sbx).

Runs a child command under user/pid/mount/net/uts/ipc namespaces with `pivot_root`,
rlimits, best-effort cgroup v2 limits, a seccomp denylist (with the x32 ABI closed),
and a deterministic environment profile — the reproducible base the typed-feedback
layer sits on top of.

**Linux only.**

## License

MIT
