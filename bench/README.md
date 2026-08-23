# bulla benchmarks — reproducing the harness leaks, signed

Three controlled experiments. Each takes ONE stand-in "solver" (no LLM — the point is to isolate the
*mechanism*, not to measure a model) and runs it under a **leaky** harness and under **bulla's seal**.
The same solver passes leaky and fails sealed, and each run emits a signed receipt saying which regime
produced the result. The input manifest — and, for `eval`, the grader digest — is identical across the
two regimes: same task, same solver, same binary, **only the seal differs.**

Run each in Linux/WSL2 after `cargo build`:

| Dir | Vector (source) | Leak mechanism | bulla defense | Result |
|---|---|---|---|---|
| `retrieval/` | **network** — Cursor, 57% of a top model's SWE-bench-Pro wins | solver GETs the fix from a host `127.0.0.1` "upstream" | no-egress net namespace (default) | leaky **PASS**/seal=BROKEN · sealed **FAIL**/seal=HELD |
| `gitmine/` | **git-history** — Cursor, 9% | solver `git log --all` → `git show <fix>:calc.py` | `--seal-git` prunes `.git` to a history-free HEAD | raw **PASS**/BROKEN · `--seal-git` **FAIL**/HELD |
| `oracle/` | **oracle-tamper** — Berkeley RDI, 100% break | solver overwrites the test + drops a force-pass `conftest.py` | `bulla eval` grades in a separate cell over the restored grader + only the solution edits | same-cell **PASS**/BROKEN · grade-cell **FAIL**/HELD |
| `flaky/` | **metric-gaming** — flaky pass laundered into pass@1 | a lucky run kept, the failures quietly dropped | every attempt chains into a tamper-evident ledger; dropping one breaks the chain (`bulla log`) | honest pass rate on the record; tampered ledger flagged **BROKEN** |
| `agent-solve/` | **a real solve** (not a leak) — a frontier agent fixes a real cross-file bug from source | — | `bulla eval` signs the outcome; baseline (no fix) must FAIL, proving the grader is real | baseline **FAIL**/HELD · agent-solve **PASS**/HELD, `network=Deny` |
| `envleak/` | **environment leakage** — instance-id path + host env | metadata reveals task/answer | closed by construction: the cell shows `/work` + a fixed env | host path never appears inside; deterministic env signed (clock = roadmap) |
| `egress/` | **smart egress** (a capability, not a leak) — a trading agent needs *scoped* network | open network would break the seal | mediated broker over a Unix socket (netns stays empty); allowlist + every call hashed into the receipt | allowed host reached, off-list **DENIED**, both signed; still **SEAL HELD** |
| `zk/` | **zero-knowledge risk proof** (a capability) — prove compliance without revealing the strategy | the position/strategy is commercially secret | a real Bulletproofs **range proof** that the order is within a committed risk cap | broker verifies **within cap = true** without seeing the order; over-cap & tampered → **false** |
| `determinism/` | **reproducibility, stated precisely** — what actually reproduces | over-claiming "the receipt reproduces" | the deterministic profile makes OUTPUT hashes reproduce; the timestamped body does not | `stdout_sha256` + `inputs_root` **identical** across two runs; `body_digest` **differs** (honest) |

```bash
bash bench/retrieval/run_experiment.sh
bash bench/gitmine/run_experiment.sh
bash bench/oracle/run_experiment.sh
bash bench/flaky/run_experiment.sh
```

Each script prints the two `bulla` runs, `bulla verify` on each receipt, and a RESULT table read
straight out of the signed receipts. They are **controlled reproductions of the leak mechanisms** behind
Cursor's 87.1% → 73.0% and RDI's 100%-break (scripted solvers, not frontier models) — signed, deterministic,
and checkable by anyone. A live many-model study is future work (needs an API key).

**Honest scope:** the "solver" stands in for an agent's retrieval/poisoning behaviour so the mechanism
is isolated cleanly (the same controlled-experiment style as the sibling `sbx` project). A real frontier
agent on a real SWE-bench-Pro instance is the next milestone; these prove the *defense*, deterministically.
