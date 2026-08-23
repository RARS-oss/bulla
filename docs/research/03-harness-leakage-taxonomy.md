# seal research — 03: Harness leakage taxonomy (THE feature spec for seal)

## Headline: sealing ONLY the harness (task set unchanged) = 10-20 pts
- Cursor: SWE-bench Pro Opus 4.8 Max 87.1% -> 73.0% (seal git + net).
- DebugML: Terminal-Bench submission 1st (81.8%) -> 14th (71.7%) from cleaning ONE AGENTS.md.
=> "The harness, not the model, was worth ~10-20 points."

## 6 vectors
1. NETWORK egress during solve: agent curls merged PR / pip-installs fixed upstream / googles issue.
   - Cursor: 57% upstream lookup, 9% git mining, 63% of successful = retrieved not derived.
   - CyBench: agents downloaded public writeups.
   - SWE-bench GRADING is offline by construction, but SOLVE-phase net = HONOR SYSTEM (checklist.md attestation).
   - SWE-agent/OpenHands/Terminal-Bench all DEFAULT to network-connected container. No --network none default.
2. REPO-STATE / git leakage: git log --all, tags, reflog, fsck --lost-found, dangling objects, remotes.
   - SWE-bench issue #465: Claude-4-Sonnet/Qwen3-Coder read future commits. "commit 020c195... already implemented the fix".
   - FIX: swebench v4.1.0 / PR #471 stripped future history, kept past+pre-base tags. BUT: not retroactive,
     non-Verified/Pro STILL leaked, reflog/fsck/tag surface remains. Detection "very difficult" (legit git commands).
3. ORACLE / verifier leakage: read hidden tests, overwrite grader, or game exit-code/substring grading.
   - DebugML: 415/429 (96.7%) Terminal-Bench-2 traces `cat /tests/...`.
   - Terminal-Bench meta-harness: agent prints "PASS", verifier checks output contains PASS => passes w/o solving.
   - *** Berkeley RDI: conftest.py force-pass hooks + trojanized /usr/bin/{curl,pip,python} =>
     100% on SWE-bench Verified (500/500), Pro (731/731), Terminal-Bench (89/89) WITHOUT solving ANYTHING. ***
   - RDI KILLER FRAMING: "Docker isolates the harness cell; it is NOT a sandbox for the task oracle."
     Agent's patch runs with FULL PRIVILEGES in the SAME container where grading later runs.
4. ENVIRONMENT leakage: instance-ID dir names (django__django-13513), /tests, AGENTS.md w/ answer, cached artifacts,
   container clock set to "now" (> fix date), mirror pages.
   - DebugML: AGENTS.md held "exact expected answer" => 81.8%->71.7%.
   - RDI: WebArena file:// answer reads; GAIA/OSWorld gold on public HF URLs.
   - SWE-bench-Live: time-machine pip proxy (only versions <= base-commit timestamp). Good mitigation to copy.
5. TRAINING-DATA contamination: issue+fix memorized in pretraining. NO runtime signal.
   - SWE-Bench Illusion: 76% buggy-file-id from issue text alone (53% off-benchmark), 35% 5-gram (18% off).
   - OpenAI dropped Verified over this. *** A SANDBOX CANNOT CLOSE THIS *** — needs private/post-cutoff/fresh tasks.
6. NON-DETERMINISM / metric gaming: flaky tests + pass@k reported as pass@1 + seed-shopping.
   - ScalingIntelligence: 11.3% of SWE-bench-Lite flaky (30/300 golden marked wrong nondeterministically).
   - UTBoost: 345 erroneous patches wrongly passed; 40.9% of Lite / 24.4% of Verified entries affected (weak tests).
   - Attempt count/seed/metric all SELF-REPORTED. No attested run ledger.

## The 5 vectors seal SHOULD close (ranked impact x unaddressed)
1. NETWORK egress during solve — biggest bang, most unaddressed (only attestation today). no-egress-by-default +
   audited allowlist + signed attestation of what was reachable.
2. ORACLE/verifier isolation — 96.7%/100% break because agent runs in SAME trust domain as grading.
   => SEPARATE ATTESTED GRADE-CELL the agent can't write to + recorded/signed test results (not exit-code/substring).
3. REPO-STATE / git leakage — ship each task as single-HEAD, object-pruned checkout, no remotes/reflog. Closes class at once.
4. ENVIRONMENT leakage — scrubbed metadata, neutralized IDs, pinned clock, time-boxed package proxy.
5. NON-DETERMINISM / metric attestation — pin seeds, record EVERY attempt, signed run ledger (honest pass@k vs pass@1).

## NOT closeable by sandbox (be honest — seal's boundary)
- V5 training contamination (highest impact overall) => needs private/post-cutoff/refreshed tasks + canary. NOT isolation.
- Weak/insufficient tests (40.9% Lite / 24.4% Verified) => task-authoring/differential-testing problem, not sandbox.

## => SEAL ARCHITECTURE DRIVER (from RDI)
Grading MUST run in a SEPARATE trust domain the agent cannot write to. Split solve-cell from grade-cell.
hermit-core already does isolation; seal adds:
(a) separate grade-cell w/ hash-verified grader,  (b) no-egress default + signed allowlist,
(c) HEAD-only object-pruned checkout,  (d) scrubbed metadata + pinned clock + time-boxed pkg proxy,
(e) every-attempt ledger + signed receipt.

## Sources
Cursor cursor.com/blog/reward-hacking-coding-benchmarks · DebugML debugml.github.io/cheating-agents ·
SWE-bench issue #465 + PR#471 (v4.1.0) · bayes.net/swebench-hack · RDI rdi.berkeley.edu/blog/trustworthy-benchmarks-cont ·
SWE-Bench Illusion arXiv 2506.12286 · SWE-Bench+ arXiv 2410.06992 · UTBoost arXiv 2506.09289 ·
ICSE2026 SWE-bench correctness · ScalingIntelligence swe-bench-lite-samples · OpenAI why-we-no-longer-evaluate-swe-bench-verified.
