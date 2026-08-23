# seal research — 04: Competitive landscape (eval harnesses)

## Headline: every harness = Docker + operator's UNSIGNED logs. None signs the run. Most leave net ON during solve.

| Framework | Isolation | Net OFF during solve? | Signed receipt? | Deterministic | Adoption |
|---|---|---|---|---|---|
| UK AISI Inspect | Docker->gVisor+Cilium->VM | YES (network_mode:none default) | NO (unsigned .eval logs) | seeds/epochs | ~2.6k*, METR migrating to it |
| METR task-standard/Vivaria | Docker+aux VM | YES (no-internet default) | NO | future goal | deprecated -> Inspect |
| SWE-bench official | Docker, PRIVILEGED (cap SYS_ADMIN) | NO (net on, deps baked) | NO (report.json) | strong (pinned imgs, F2P/P2P) | ~5.7k*, INDUSTRY STD |
| Terminal-Bench v2 Harbor | Docker Compose + tmux | NO | NO (best replay: asciinema) | pinned, state-based pytest | ~2.5k*, rising |
| OpenHands | Docker runtime (or none) | NO | NO | pins SWE imgs | ~84.8k* most-adopted |
| SWE-agent + SWE-ReX | Docker->Modal/Fargate | NO/unenforced | NO (.traj) | per-instance imgs | ~20.1k* |
| Princeton HAL | conda/Docker/Azure VM | NO (web agents need net) | NO (Weave; AES=anti-contam NOT integrity) | cost-controlled | ~311*, archived |
| Epoch AI | on Inspect (API) | N/A | NO (public log viewer) | multi-sample SE bars | evals org |
| lm-eval-harness | NONE (in-process) | No | NO (logs seed+version+commit) | best pure-model (seed,cache) | ~13.8k* |
| OpenBench (Groq) | on Inspect | No | NO | seed; warns non-repro | ~807* |
| HELM | NONE in-process | No | NO | request cache | ~2.9k* |
| Commercial (Braintrust/LangSmith/Patronus/Arize/Langfuse) | none (SaaS trace DB) | N/A | NO (DB "audit trail" != crypto) | versioned datasets | well-funded |

## Attested/verifiable cluster (adjacent, NOT eval harnesses)
- *** Attestable Audits (Cambridge, arXiv 2506.23706): runs benchmark INSIDE a TEE, remote attestation signs eval code ran
  in trusted image untampered. THE closest prior art to seal — but HARDWARE-TEE-BOUND (TDX/SGX/SEV/H100). Research prototype. ***
- Axiomark (axiomark.dev): "evidence infra" capture->seal(ed25519+content hash)->hash-chain->open verifier. Attests WHICH INPUTS
  model saw / what it output — NOT isolation. Early, 4 US provisionals filed 2026. <= closest SOFTWARE-signed, wrong target.
- Ghost Mesh/VeriTrace: offline-verifiable hash-chained "trust receipts" of an AI decision. Early/marketing.
- Ontology (ont.io): W3C Verifiable Credentials + DIDs for evaluator provenance. Concept.
- Azure Confidential AI / Phala GPU-TEE: TEE-served INFERENCE attestation. Production but inference, not eval.
- Adjacent confinement (no receipt): Sandlock (arXiv 2605.26298, Rust, Landlock+seccomp, rootless) <== does seal's ISOLATION
  WITHOUT the receipt = thin-moat risk. Microsandbox (libkrun ~320ms), Firecracker (~125ms), gVisor, E2B/Modal/Daytona.

## WHITESPACE seal owns
1. Receipt about the ENVIRONMENT not just bytes: bind {task digest, ENFORCED sandbox policy (net=default-deny, rootless, fs scope,
   seccomp/Landlock ruleset), env/image digest, transcript hash, score}. seal signs "network was PROVABLY off, ran rootless under
   THIS policy, here's the score THAT policy produced." Axiomark signs inputs-seen; that specific env-claim is UNCLAIMED.
2. Default-deny network as an ATTESTED property (Inspect/METR turn it off; nobody SIGNS that it was off).
3. "SLSA/in-toto for evals" — never ported. seal = that port (in-toto attestation + optional Rekor anchor).
4. Operational wedge: rootless ~ms startup, no /dev/kvm, no root => runs per-instance across 2000+ tasks in UNPRIVILEGED CI where
   SWE-bench SYS_ADMIN container & microVMs (KVM 125-320ms) can't go cheaply. TEE can't scale to per-instance-per-model economics.
   seal trades hardware-grade soundness for near-free ubiquity.
5. Be the SUBSTRATE not another benchmark: ship as a SIGNING SANDBOX BACKEND that Inspect/SWE-bench/Terminal-Bench/Harbor plug in.
   (Inspect already has pluggable sandbox-provider iface; SWE-ReX a deployment abstraction.)

## RISKS (and how to play them)
1. HARD-TRUST: software-signed receipt only as honest as seal binary + host. Malicious lab runs doctored build -> false receipt.
   => seal = tamper-EVIDENCE + reproducibility, NOT tamper-PROOF vs malicious prover. HONEST FRAME: "signed commits + reproducible
   builds for evals." Decisive in COOPERATIVE/semi-trusted world (labs->auditors, reputation-staked leaderboards, own CI, anyone
   can re-run & reproduce signed digest). NOT a ZK proof. Adversarial tier = optional TEE (TDX/SEV) + Sigstore/Rekor anchor.
   Get scoping wrong -> reviewers call it security theater. <== THIS IS THE #1 THING TO NAIL (matches sbx/andromeda honesty signature).
2. TEEs heavy = the opportunity. ~90% value (evidence+repro+provenance+net-attestation) at ~1% cost, hardware-optional.
3. Market pull weak-but-rising. All rivals (Axiomark/VeritasChain/Ghost Mesh/Ontology) 2026-vintage, pre-product. Timing risk real
   but thesis validated. Drivers: contamination disputes, EU AI Act Art.12, NIST AI RMF, model-substitution auditing (arXiv 2504.04715).
4. DETERMINISM CEILING: can't make MODEL outputs bit-repro (system_fingerprint drift, GPU nondeterminism). Scope claim to
   "deterministic ENVIRONMENT + signed recorded transcript" NOT deterministic model, or it gets picked apart.
5. Commoditized primitives / thin moat / NAME COLLISION ("seal" overloaded). Moat = receipt semantics + determinism + hermeticity
   binding + harness integrations. If underbuilt, seal = "Sandlock + a signature".

## NET
Differentiation real+specific: a rootless ~ms hermetic sandbox that SIGNS a re-checkable receipt binding enforced isolation policy
to the score, plugging in UNDER existing harnesses. Nobody ships it. It sits in a trust valley (heavier than "just log it", lighter/
less-sound than TEE). Wins ONLY if: (a) scrupulously honest about cooperative/reproducibility threat model, (b) optional TEE/tlog
anchor for adversarial, (c) ships as drop-in verifiable-isolation BACKEND for Inspect/SWE-bench/Terminal-Bench, not yet another benchmark.

Sources: Inspect UKGovernmentBEIS/inspect_ai · METR task-standard/vivaria · SWE-bench run_evaluation.py (no network_mode) ·
Terminal-Bench laude-institute · OpenHands All-Hands-AI · SWE-agent/SWE-ReX · HAL princeton-pli · Epoch · lm-eval-harness ·
OpenBench groq · HELM · Attestable Audits arXiv 2506.23706 · Axiomark axiomark.dev · Sandlock arXiv 2605.26298 · arXiv 2504.04715.
