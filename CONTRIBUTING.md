# Contributing to bulla

Thanks for taking a look. bulla is a small Rust workspace; contributions and questions are welcome.

## Layout

- `crates/hermit-core` — the isolation mechanism (vendored from [RARS-oss/sbx](https://github.com/RARS-oss/sbx)).
- `crates/bulla-core` — the receipt model (policy, manifest, hash-chained log, Ed25519 sign/verify). Pure, platform-independent, fixture-tested.
- `crates/bulla-cli` — the `bulla` binary (`run | eval | verify | log | keygen`).
- `bench/` — the leak reproductions; each is a controlled experiment with signed receipts.
- `docs/` — the technical report, figures, and the prior-art research.

## Before you open a PR

The sandbox is Linux-only (user namespaces). Develop on Linux or WSL2; point `CARGO_TARGET_DIR` at a
native path for speed. Then:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # must be clean
cargo test --workspace                                   # unit tests
bash bench/retrieval/run_experiment.sh                   # (and the other bench/ scripts)
```

CI runs all of the above plus the four leak reproductions and the real agent-solve. Keep the honest
threat model intact: never claim a guarantee the design doesn't provide (see `docs/REPORT.md` §7).

## Design rules

- `bulla-core` never touches the OS; `hermit-core` never touches crypto; the CLI wires them.
- Serialized types are deterministic (no `HashMap`) so digests are stable.
- New receipt fields are `#[serde(default)]` so older receipts still parse.

MIT licensed; by contributing you agree your work is released under it.
