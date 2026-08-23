# Security model & audit status

`bulla` runs **untrusted code**, so its boundary is stated plainly.

## Threat model

- **In scope (the primary adversary):** untrusted code running *inside* the cell (e.g. a reward-hacking
  agent). It must not be able to reach the network unbidden, tamper with the grader, mine the fix from
  `.git`, forge or steal the signing key, or forge the signed receipt / ledger / egress log.
- **In scope (cooperative reporting):** a receipt is *tamper-evident* and its **output digests are
  reproducible**, so a third party who trusts the signing key can re-check a result. A tampered receipt
  fails `bulla verify`.
- **Out of scope (documented, not defended):** a prover who forges the `bulla` **binary** *and* controls
  the host. That adversary needs the hardware-TEE tier (`bulla attest`, real-hardware version = roadmap).
  Also out of scope for a sandbox: training-data contamination and weak tests (task-authoring problems).

## Audit

An adversarial security review was run against the whole codebase (`crates/*`, `adapters/mcp`). Summary:

**Verified sound (no change needed):** receipt verification (signature via `verify_strict` + body digest
+ event chain; no bypass), deterministic canonical serialization (sign and verify use the same serializer
over the same body; no `HashMap` in the signed body), the MCP adapter (argv list, no shell injection), and
the `attest` simulation (clearly labelled, non-authoritative).

**Fixed before publication:**

| ID | Severity | Issue | Fix |
|----|----------|-------|-----|
| C1 | Critical | signing key + ledger + egress log lived in the cell-writable `/work/.bulla`, and the key was loaded *after* untrusted code ran → the cell could plant/steal the key or forge the signed logs | key/ledger/egress-log moved to a **host-only per-work-dir state dir** outside the mount; key loaded **before** the cell; `--key`/`--ledger` inside the work dir are refused |
| H1 | High | fail-open: if the sandbox couldn't be built, the command silently ran unconfined on the host | **fail-closed** by default; running without isolation now requires the explicit `--allow-no-sandbox` flag |
| H2 | High | egress allowlist checked host only (port/path/IP attacker-controlled) → SSRF to any local port / internal IP via a rebound name | allowlist grammar is `host[:port]` (bare host = 80/443 only); resolution is **pinned**; internal IPs are blocked unless allowlisted as a literal address; the resolved IP is recorded in the receipt |
| M1 | Medium | egress broker had unbounded request/response and no read timeout | request line capped (8 KiB), response capped (4 MiB, `Read::take`), read timeout on the socket |
| M3 | Medium | predictable, symlink-unsafe temp dir for the grade view | unpredictable name + exclusive `create_dir` (fails if the path exists) |
| L1 | Low | egress socket was `0666` | `0600` (the in-cell client shares the invoking uid) |
| L3 | Low | `short()` sliced by byte index (latent panic on a multibyte boundary) | char-safe truncation |
| N1 | Medium | the receipt write followed a symlink an in-cell process could plant at `--out` in `/work`, allowing arbitrary host-file overwrite (e.g. corrupting the host-only ledger / signing key = DoS) | receipt defaults to the host-only state dir; the path is unlinked before writing (a symlink is removed, not followed), in both `run` and `eval` |
| N2 | Medium | `is_internal` (egress SSRF filter) missed IPv4-mapped IPv6 (`::ffff:169.254.169.254`) and CGNAT `100.64/10`, re-opening SSRF via a DNS name | classify mapped addresses on their v4 form; add CGNAT |

A second, independent re-audit verified all of the above and confirmed the crypto verification, canonical
serialization, fail-closed fallback, and egress pinning are sound. Each fix is covered by a test or a
`bench/` assertion (e.g. `--key` inside the work dir is refused; an allowlisted host on a non-allowlisted
port is denied; `is_internal` blocks mapped-IPv6 / CGNAT).

**Known / deferred (tracked, lower priority):**

- **M2** — `bulla verify` reports `sig_ok`/`intact` against the *embedded* pubkey; there is no keyring
  pinning yet. `sig_ok` means "internally consistent + unforged", **not** "signed by a key you trust".
  Planned: `bulla verify --pubkey/--keyring`. Until then, pin the expected key out of band.
- **M4** — `hash_work_dir`/`snapshot_dir` read files fully into memory (no per-file/aggregate cap).
  Planned: streamed hashing + size limits. Give `bulla` a bounded work dir for now.
- **L2** — the git preflight runs the host `git` against an attacker-controlled tree; `--seal-git`
  re-inits (dropping hooks/config), but the unsealed path runs `git rev-parse`. Planned: run git with
  `GIT_CONFIG_NOSYSTEM=1` + empty `HOME` + `core.hooksPath=/dev/null`, or inside a cell.
- **Ledger tail-truncation** — a backward hash chain detects interior deletion but not truncation of the
  most recent entries; that needs an external witness (planned Rekor/transparency-log anchor).
- **N3 (low)** — the vendored `hermit-core` scratch dir uses a predictable name + `create_dir_all`
  (the CLI's grade-view temp dir was hardened; the vendored one is a follow-up, and needs a local
  attacker on shared `/tmp` — outside the primary threat model).
- **N4 (low)** — the egress broker has no *write* timeout to the in-cell client (self-inflicted stall;
  the broker is killed after the run) and copies a bare `\r` in a path into the (already host/port-pinned)
  request line. Planned: write timeout + reject control chars in the path.

## Reporting

This is a research/portfolio project. If you find an issue, open a GitHub issue (or, for something
sensitive, contact the maintainer via the GitHub profile) rather than posting exploit details publicly.
