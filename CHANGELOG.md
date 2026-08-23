# Changelog

All notable changes to bulla are recorded here. Format loosely follows Keep a Changelog.

## [0.1.0] — unreleased

The first working slice: a hermetic eval cell that emits a signed, re-checkable receipt that the seal held.

### Added
- **`hermit-core` cell** — `clone(2)` into user/pid/mount/net/uts/ipc/cgroup namespaces, tmpfs root +
  read-only host binds, `pivot_root`, seccomp-bpf denylist, rlimits, deterministic environment; no root,
  no daemon, ~4.6 ms startup (reused from RARS-oss/sbx).
- **`bulla-core` receipt** — `EvalPolicy`, content-addressed input `Manifest`, `AppliedSummary`,
  `OutcomeSummary` (outputs by sha256), a hash-chained event log, and Ed25519 sign/verify over the
  canonical body. `evaluate_seal(policy, applied, git_sealed, oracle_isolated)` recomputes the hermetic
  verdict. 7 unit tests.
- **`bulla` CLI** — `run` (sealed run → signed receipt), `eval` (two-cell solve→grade with a restored
  grader view), `verify` (offline signature/digest/chain + seal verdict; non-zero on tamper), `log`
  (tamper-evident run ledger + honest pass rate), `keygen`.
- **`--seal-git`** — prune the work dir's git history to a single history-free HEAD so the fix can't be
  mined from `.git`; recorded as `git_sealed` in the receipt.
- **Run ledger** — every attempt chains via `ledger_prev` + hash; dropping an interior attempt breaks the
  chain. Anti-cherry-pick / honest pass@k.
- **Smart egress** (`--egress-allow <host>`) — capability-based mediated network: the cell keeps an empty
  network namespace (no raw egress) and reaches an allowlisted host only through a Unix-socket broker; the
  allowlist and a hash-chained log of every request/response are folded into the receipt, and the run stays
  SEAL HELD. Off-list hosts are refused and recorded. The broker runs as a separate process to preserve
  the single-threaded-before-`clone` invariant.
- **Four leak reproductions** (`bench/`) — network egress, git-history mining, oracle tamper, metric gaming;
  each a signed leaky-vs-sealed contrast. Plus a real agent solve (`bench/agent-solve/`).
- **`bulla-zk`** — a real zero-knowledge (Bulletproofs) range proof that a secret order/position is within
  a committed risk cap, revealing neither the value nor the strategy. Complements the sandbox: the receipt
  proves sealed execution; the zk proof proves the order is bounded, privately. (`crates/bulla-zk`, 4 tests +
  `examples/risk_proof.rs`.)
- **`bulla attest`** (TEE tier, honest) — detects a hardware enclave (SEV-SNP / TDX / SGX / Nitro) and,
  with `--simulate`, prints a clearly-labelled simulation of the attestation flow that binds a receipt
  digest to an enclave-resident key. Never presents the mock as a real quote; real hardware attestation is
  future work.
- **`--json`** on `run`, `eval`, and `verify` — compact machine-readable output for tooling.
- **MCP adapter** (`adapters/mcp/bulla_mcp.py`) — exposes `run_attested` and `verify_receipt` so any MCP
  client (Claude Desktop, Cursor, Windsurf, Cline) runs a model's code in the sealed cell and gets back a
  signed, verifiable receipt as structured content instead of raw stdout.
- **Docs** — `docs/REPORT.md`, figures, a GitHub Pages landing (`docs/index.html`), and the prior-art
  research under `docs/research/`.
- **CI** — fmt/clippy/test/build plus every bench reproduction, the agent solve, smart egress, the zk
  proof, the determinism check, and the MCP wrapper.
- **CLI integration tests** (`crates/bulla-cli/tests/cli.rs`) — invoke the real binary: run → verify,
  tamper detection, keygen. 15 tests total across the workspace.
- **`bench/determinism/`** — proves the reproducibility claim *precisely*: the deterministic profile makes
  output hashes (`stdout_sha256`, `inputs_root`) reproduce byte-for-byte, while the timestamped signed body
  does not — so a third party re-checks the outputs, not the `body_digest`.

### Polish / honesty (self-review pass)
- Corrected the reproducibility wording everywhere: what reproduces is the **output digests**, not the
  signed body (which carries a timestamp + per-run key).
- Reframed the bench reproductions as **controlled reproductions of the leak mechanisms** (scripted solvers),
  not re-runs of the frontier-model studies — a live many-model study is future work.
- Marked `hermit-core` clearly as **vendored** from RARS-oss/sbx.
- Removed dead code (the unused `Error`/`Result` types and the `thiserror` dependency in `bulla-core`).

### Boundary (by design, see REPORT §7)
- Tamper-evidence + provenance + reproducibility, **not** a proof against a malicious prover who forges the
  binary and controls the host (that is the optional TEE tier).
- Does not address training-data contamination or weak tests — out of scope for a sandbox.
