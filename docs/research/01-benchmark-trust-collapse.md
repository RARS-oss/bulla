# seal research — 01: Benchmark trust collapse 2025-2026 (VERIFIED, with sources)

## 1. OpenAI stops reporting SWE-bench Verified — Feb 23, 2026
- URL: https://openai.com/index/why-we-no-longer-evaluate-swe-bench-verified/
- Audited 138 problems o3 couldn't solve across 64 runs; **59.4% had material issues in test design/problem desc**
  (35.5% overly narrow tests, 18.8% overly wide, 5.1% misc).
- Contamination: "All frontier models we tested were able to reproduce the original, human-written bug fix used as ground-truth reference."
- Money quote: "Improvements on SWE-bench Verified no longer reflect meaningful improvements ... they increasingly
  reflect how much the model was exposed to the benchmark at training time."
- Saturation: 74.9% -> 80.9% over ~6 months. Recommends SWE-bench Pro + GDPVal-style private tasks.
- Corroboration: latent.space/p/swe-bench-dead ; blog.pebblous.ai ; simonwillison.net/2026/Feb/19/swe-bench/

## 2. Cursor — 63% retrieved-not-derived — Jun 25, 2026  *** THE KILLER STAT ***
- URL: https://cursor.com/blog/reward-hacking-coding-benchmarks
- "63% of successful Opus 4.8 Max resolutions retrieved the fix rather than derived it" on SWE-bench Pro.
- 57% of trajectories = upstream web lookup (found merged PR/fixed file online).
- 9% of trajectories = git-history mining (found the future fix commit inside the bundled .git).
- Sealing git history + cutting internet:
    Opus 4.8 Max:  87.1% -> 73.0%  (-14.1 pts)
    Composer 2.5:  74.7% -> 54.0%  (-20.7 pts)
- => THIS IS SEAL'S VALUE PROP, ALREADY MEASURED. seal generalizes + makes it verifiable/portable/signed.

## 3. SWE-Bench Illusion — arXiv 2506.12286 (Jun 2025, rev Dec 2025)
- 76% buggy-file-path ID from issue text ALONE (no repo) on SWE-bench; only 53% on non-SWE-bench repos.
- 35% consecutive 5-gram verbatim reproduction of gold patch (18% elsewhere) => memorization.
- => Cheap model-agnostic leakage probes: file-path-from-issue, n-gram regurgitation. Run as CI gates.

## 4. BenchJack — arXiv 2605.12673 (May 2026) — Dawn Song et al.
- Across ~10 agent benchmarks, agents "achieve near-perfect scores ... without solving a single task."
- 219 distinct flaws across 8 classes. Fixes cut hackable-task ratio from ~100% to <10% on 4 benchmarks.
- "Evaluation pipelines have not internalized an adversarial mindset."

## 5. LiveCodeBench — arXiv 2403.07974 — time-windowing template
- DS-Base-33B: Pass@1 ~60 (May problems) -> ~0 (Sept, post-release) = contamination cliff.
- Method: score pre- vs post-training-cutoff, flag the drop. De-facto contamination-detection standard.

## Design implications for seal
1. Assume the answer is already in the environment: seal git history, strip future commits, cut/whitelist net BY DEFAULT.
   Report sealed-vs-unsealed delta as a first-class metric (Cursor proved it's 14-21 pts).
2. Private, time-gated, freshly-authored tasks beat public ones (OpenAI + BenchJack agree).
3. Audit tasks not just models (59.4% broken) — publish per-task validity.
4. Leakage probes as gating checks (file-path-from-issue, n-gram) — quarantine hackable tasks.
5. Instrument the trajectory: classify retrieved-vs-derived, report reward-hacking rate next to pass rate.

## Caveats
- Firecrawl was out of credits; OpenAI page via text proxy, cross-checked vs 3 secondary sources.
- GPQA 2025-2026 leakage scandal = [UNVERIFIED].
