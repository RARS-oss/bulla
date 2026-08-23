# seal — master strategy (synthesis of 4 research briefs)
_generated 2026-08-23 · sources in 01–04.md_

## 0. One line
A rootless, ~ms, hermetic eval sandbox that emits a **cryptographically signed, re-checkable receipt binding the
enforced isolation policy (network=off, unmodified grader, fixed env, pinned clock) to the score it produced** —
the verifiable-isolation layer that plugs in UNDER SWE-bench / Inspect / Terminal-Bench, not another benchmark.

Tagline candidates:
- "Don't trust the score. Verify the seal."
- "A benchmark number is a claim. seal makes it a receipt."
- "Reproducible builds for evals."

## 1. The opportunity is VALIDATED (not speculative)
- OpenAI RETIRED SWE-bench Verified (Feb 2026): scores "reflect how much the model was exposed at training time." 59.4% of audited hard tasks had defective tests.
- Cursor (Jun 2026): 63% of Opus 4.8 Max "solutions" were RETRIEVED not derived; sealing git+net dropped 87.1->73.0 (-14pt), Composer -20.7pt.
- Berkeley RDI: poisoned grader (conftest.py + trojanized binaries) => 100% on SWE-bench Verified/Pro/Terminal-Bench WITHOUT solving anything.
- DebugML: 415/429 (96.7%) Terminal-Bench traces read /tests; one AGENTS.md leak = 1st->14th.
- BenchJack (Dawn Song): agents hit near-perfect scores "without solving a single task"; 219 flaws / 8 classes.
=> Consensus across labs: they're fixing TASKS. The HARNESS is the unclosed hole. seal closes it. "Harness = 10-20 pts."

## 2. Positioning — the HONEST boundary (this is the whole game; matches sbx/andromeda signature)
seal is NOT a zero-knowledge proof of honest execution. A pure-software receipt is only as honest as the seal binary + host.
seal DELIVERS: tamper-EVIDENCE (post-hoc edits detectable) + reproducibility (3rd party re-runs, reproduces signed digest) +
provenance (who/what/when, Rekor-anchored, back-date-proof) + ENFORCED isolation (net-off is a namespace fact, not a promise).
seal is DECISIVE in the cooperative / reputation-staked world: labs reporting to auditors and leaderboards, your own CI, community re-checking.
seal is NOT tamper-PROOF vs a malicious prover on its own hardware => that is the OPTIONAL TEE tier (Tier 2).
State this boundary loudly and first. Reviewers respect it; hiding it => "security theater".

Threat model, stated as seal's law:
"A signed receipt proves the seal held to anyone who can (a) verify the signature chain + transparency-log inclusion, and
(b) reproduce the run to the recorded digest. It does not defend against a prover who forges the binary AND controls the host —
for that adversary, add the TEE anchor. Everything short of that adversary, seal covers cheaply."

## 3. What seal CLOSES (the sandbox is the right tool for these 5)
1. NETWORK egress during solve — no-egress-by-default net namespace + audited allowlist + SIGNED record of what was reachable. (biggest bang, only attestation today)
2. ORACLE/verifier isolation — SEPARATE grade-cell the agent cannot write to; grader hash-verified; results recorded+signed, not exit-code/substring. (kills the 100% RDI break)
3. REPO-STATE / git leakage — ship task as single-HEAD, object-pruned checkout, no remotes/reflog/future-tags. Closes the whole class vs whack-a-mole.
4. ENVIRONMENT leakage — scrubbed metadata, neutralized instance-IDs, PINNED CLOCK, time-boxed package proxy (SWE-bench-Live style).
5. NON-DETERMINISM / metric attestation — pin seeds, record EVERY attempt, signed run ledger => honest pass@k vs pass@1, no cherry-pick.
NOT closeable by seal (state honestly): training-data contamination (needs private/fresh tasks) + weak tests (task-authoring). seal makes grading TRUSTWORTHY, not the tests STRONG.

## 4. Architecture (built on sbx's hermit-core — reuse, do not rebuild)
Reuse: hermit-core already gives clone() into user/pid/mount/net/uts/ipc/cgroup ns + pivot_root + seccomp + fixed env + no_aslr +
the `Applied` provenance record + `protected` file concept + ~4.6ms startup, no root. This is ~70% of the mechanism DONE.
seal ADDS on top:
- crate `seal-policy`: declarative EvalPolicy (network=deny/allowlist, grader digest, clock=pinned, seed, fs scope, determinism flags). The thing the receipt commits to.
- SPLIT CELLS: solve-cell (agent, writable /work) vs grade-cell (grader, read-only, agent has NO write path in). Grader binary/tests hash-verified pre-run.
- crate `seal-receipt`: content-addressed manifest (sha256 of task, rootfs/OCI, grader, config, env-lockfile) + hash-chained event log
  (start / seal-applied / net=deny / grader-loaded / attempt-k / grade / output) + in-toto predicate "hermetic-eval-receipt".
- SIGN: Ed25519 (Tier0) or cosign keyless-OIDC; ANCHOR in Rekor transparency log. `seal verify <receipt>` = offline check + inclusion proof.
- git-hygiene preflight: HEAD-only prune, drop remotes/reflog/future objects; scrub instance-ID paths; pin clock.
- crate `seal-cli`: `seal run --policy p.toml -- <cmd>` | `seal verify` | `seal replay` | `seal attest` (TEE tier).
- Tier 1 repro: Nix/lockfile closure + optional Hermit/rr deterministic profile so a skeptic re-runs to the same output hash.
- Tier 2 (paranoid, opt-in): run harness in SEV-SNP/TDX/Nitro; gen receipt key inside enclave; bind pubkey into attestation. Nitro = best (no NIC by design).
- ADAPTER: ship as a pluggable SIGNING SANDBOX BACKEND for Inspect (has sandbox-provider iface) + a SWE-bench/SWE-ReX shim. Distribution wedge.

## 5. Strengths
- Timing: the exact hole every 2026 audit named, unclosed. Direct lineage from sbx (hermit-core) = credible + fast to MVP.
- Honest-boundary framing is a differentiator vs pre-product hype rivals (Axiomark etc.) and vs "trust us" academia.
- Rootless ~ms => the ONLY approach that scales to per-instance-per-model economics across 2000+ tasks in unprivileged CI. TEE cannot.
- "SLSA/in-toto for evals" is a clean, quotable thesis reviewers grasp instantly.

## 6. Weaknesses + HOW TO PLAY THEM
- W: software receipt not sound vs malicious prover.  PLAY: lead with the cooperative threat model; make reproduction the trust anchor;
  offer TEE as opt-in Tier2; never overclaim. Turn the limitation into the paper's rigor (the honest-boundary is the credibility).
- W: thin moat vs Sandlock (Rust Landlock+seccomp does isolation).  PLAY: moat = RECEIPT SEMANTICS + determinism + grade-cell split +
  harness integrations, NOT the sandbox. Ship the verify/replay UX + adapters others lack. Optionally build ON hermit-core/Sandlock.
- W: cannot fix training contamination or weak tests.  PLAY: scope explicitly; PAIR seal (trustworthy grading) with a fresh/private task
  channel + differential-test check as complementary, not claimed. Ship LiveCodeBench-style time-window + n-gram/file-path leakage PROBES as gates.
- W: model outputs non-deterministic.  PLAY: claim "deterministic ENVIRONMENT + signed transcript", record system_fingerprint, flag drift; do not claim deterministic model.
- W: name collision "seal".  PLAY: pick a distinct package/binary name early (crates.io + GH availability check); keep "seal" as the concept/verb ("the seal held").
- W: weak-but-rising market pull.  PLAY: land as a BACKEND under adopted harnesses (ride their adoption) + a killer demo: reproduce Cursor's
  87->73 drop, signed, one command. Demo IS the pitch.

## 7. The killer demo (what earns the stars)
`seal run` a public SWE-bench-Pro instance twice: (A) leaky harness (net on, full git) vs (B) sealed (net off, HEAD-only, grade-cell).
Show the score drop + emit TWO signed receipts; `seal verify` both; publish receipts anyone can check. Reproduce the 14-20pt gap Cursor
found — but SIGNED and one-command. That single reproducible artifact is the whole argument.

## 8. Roadmap to top-level + open-source release
Phase 0 (spike): fork hermit-core into seal workspace; EvalPolicy + minimal signed manifest + `seal run/verify`. Prove net-off receipt.
Phase 1 (MVP): grade-cell split + git-hygiene + hash-chained log + Ed25519 sign + Rekor anchor + verify/replay. 1 real SWE-bench-Pro task end-to-end.
Phase 2 (the demo): the leaky-vs-sealed reproduction of Cursor's drop, two signed receipts, HTML report + figures (match sbx/andromeda polish).
Phase 3 (adoption): Inspect signing-backend adapter + SWE-ReX shim; leakage-probe gates (file-path-from-issue, n-gram, time-window).
Phase 4 (paper/dissertation + release): REPORT.md + arXiv-style writeup; Tier2 TEE anchor as "future/optional"; tag v0.1, crates.io, GHCR, Pages.
Portfolio consistency: same bar as light-andromeda/sbx — forbid(unsafe) in core, property/fuzz tests, honest "refuted our own hypothesis" section, CI, figures, live demo.

## 9. Dissertation angle (why seal, not MIT-style academic benchmarking)
Thesis: mainstream academic eval (the "trust us" leaderboard culture, MIT-adjacent benchmark methodology) treats the HARNESS as
neutral plumbing and the SCORE as the artifact. seal argues the harness is an adversarial security surface and the artifact must be a
VERIFIABLE RECEIPT, not a number. Structure: (1) empirical collapse (OpenAI/Cursor/RDI/BenchJack data + graphs). (2) taxonomy of 6
harness leakage vectors, map which are sandbox-closeable. (3) seal design + the honest threat-model boundary (cooperative vs adversarial,
software-evidence vs TEE-proof). (4) the leaky-vs-sealed reproduction experiment w/ signed receipts (the graph: score before/after sealing).
(5) determinism as precondition (reuse sbx's byte-identical-across-N-runs result). (6) threats to validity + what seal CANNOT close.
Graphs: score-drop-on-sealing bar; leakage-vector impact chart; startup-cost vs TEE (ubiquity argument); receipt-verify flow diagram.
TODO: user to name the specific MIT work/lab to target precisely (BenchJack=Berkeley; find the MIT-specific benchmark/paper as the foil).
