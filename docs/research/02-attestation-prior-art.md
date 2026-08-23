# seal research — 02: Verifiable/attested execution prior art

## Two trust models
- (A) TRUST-THE-SIGNER: crypto integrity + tamper-evidence. Cheap, no HW. Proves WHAT ran + receipt unforged.
      Relies on runner being honest about isolation.
- (B) TRUST-THE-HARDWARE: TEE remote attestation. Expensive, HW/root-bound. Proves unmodified image on genuine silicon.

## THE key nuance (seal's honesty axis)
Nothing off-the-shelf attests the RUNTIME POLICY ("network was actually off").
TEEs attest a LOAD-TIME MEASUREMENT. "No network" holds in Nitro only because the enclave has NO NIC by design (structural).
=> seal's move: hermit-core ALREADY creates a fresh empty net namespace (CLONE_NEWNET, only lo up) = STRUCTURALLY networkless,
   the same principle as Nitro's no-NIC. So seal can make a STRONG, HONEST no-network claim at Tier 0 WITHOUT a TEE,
   because isolation is enforced by the namespace mechanism + re-checkable by reproduction, not merely asserted.

## Load-bearing primitives (cheap tier)
- cosign attest-blob --predicate receipt.json --type <custom-URI>  => DSSE in-toto attestation, uploadable to Rekor.
  This is THE primitive for a publicly auditable receipt. LOW cost, no HW, no root.
- Sigstore = cosign + Fulcio (keyless OIDC short-lived certs) + Rekor (append-only transparency log, Trillian-backed).
- in-toto attestation = {subject(name+digest), predicateType, predicate}. Define predicateType "hermetic-eval-receipt".
- SLSA provenance (L3 = builder can't forge) — conceptual cousin of "receipt runner can't forge". For grader build lineage.
- GitHub Artifact Attestations (actions/attest) — free for public repos.

## Reproducibility / determinism (Tier 1)
- Nix / NixOS: hermetic sandboxed builds, content-addressed pinned closures => makes "fixed environment" checkable by hash.
- Hermit (Meta, facebookexperimental/hermit): FORCES determinism (time, thread interleave, RNG), gates syscalls => backs
  "deterministic profile" + "no network" claims. rr (Mozilla) = record/replay bit-identical.
- Reproducible builds (Debian 14 Forky will BLOCK non-reproducible pkgs) => kills "modified grader".
- Mechanism: skeptic re-runs, checks output hash == receipt. Removes signer-trust for the reproduced part.

## Verifiable ML eval / attested inference
- zkML (EZKL, ZKML EuroSys'24, zkLLM): proves model output correct, no HW — but INFEASIBLE at LLM eval scale (prover cost).
- TEE decentralized inference: Atoma (TDX+SNP+CC-GPU + sampling consensus), Ambient (Proof-of-Logits [UNVERIFIED soundness]).
- EQTY Lab "Verifiable Compute" (Intel+NVIDIA, Dec 2024) = CLOSEST COMMERCIAL: issues a browser-verifiable certificate that
  an attested AI computation ran. But heavyweight/silicon-rooted, governance/compliance-framed, NOT a hermetic eval seal.
- IMPORTANT: academic "verifiable benchmarking" solves CONTAMINATION ("did model memorize answers"), NOT "did the seal hold".

## Lightweight hash-chained logs (Tier 0 backbone)
- Content-addressed run manifest: sha256 of grader, harness OCI digest, Nix closure, config, dataset, model weights + invariants.
- Hash-chained append-only event log (Crosby-Wallach tamper-evident history tree, USENIX'09): retroactive edit breaks the chain.
- Merkle transparency logs: CT/RFC6962, Google Trillian, Rekor (=Trillian, so Area2 & Area5 converge). research.swtch.com/tlog.
- CLOSEST FRESH PRIOR ART: PunkGo — "Right to History: A Sovereignty Kernel for Verifiable AI Agent Execution"
  (Jing Zhang, arXiv 2602.20214) — hash-chained append-only log for tamper-evident AI AGENT execution, CT-inspired, TEE-optional.
  Essentially the lightweight receipt design applied to agent runs. => seal must differentiate: seal = the SANDBOX + the receipt
  fused (isolation enforced AND attested), not just a log wrapper.

## Recommended LAYERED design for seal
- TIER 0 (default, no HW, LOW): content-addressed manifest + hash-chained event log + custom in-toto predicate,
  signed w/ cosign (Ed25519 or keyless), anchored in Rekor. Proves: unmodified grader (digest), declared env, no-network
  (net_ns enforced), output integrity, unforgeable/back-date-proof receipt. Trust: honest runner host.
- TIER 1 (LOW-MED): Nix/reproducible closure + Hermit/rr deterministic profile. Publish so 3rd party re-executes & confirms
  output hash. "no network" enforced by sandbox, not asserted. => removes trust for everything reproducible.
- TIER 2 (MED-HIGH, HW): VM TEE (SEV-SNP / TDX) or AWS Nitro Enclave. Gen receipt keypair INSIDE enclave, bind pubkey into
  attestation. Nitro = sweet spot (no network/storage BY DESIGN => "no network" structurally attested). +NVIDIA CC-GPU if GPU inference.

## THE OPEN GAP (seal's territory)
No off-the-shelf tool produces "a signed receipt that a hermetic eval sandbox's isolation invariants
(no network, fixed env, unmodified grader, deterministic profile) ACTUALLY HELD."
Every existing option attests an ADJACENT fact. Attesting runtime isolation POLICY (vs load-time measurement) is
essentially unsolved outside structurally-networkless enclaves. => seal owns: sandbox-enforced invariants + signed receipt + reproducible.
