//! bulla-core — the receipt model.
//!
//! A **bulla** is a signed, self-verifying record that a sandboxed evaluation ran under a stated
//! isolation policy and was not tampered with. It binds, in one artifact:
//!
//! * the **policy** the run committed to (network off, deterministic env, wall limit, …) + its digest,
//! * a **content-addressed manifest** of the inputs (sha256 of every file in the work dir),
//! * the **applied isolation** the sandbox actually achieved (namespaces, seccomp, pivot_root, …),
//! * the **outcome** (exit, wall time, and the sha256 of stdout/stderr — the bytes, by hash),
//! * a **hash-chained event log** of the run, and
//! * an **Ed25519 signature** over the canonical bytes of all of the above.
//!
//! Threat model (stated honestly): a bulla gives **tamper-evidence + provenance**. It proves the
//! record is unforged *to anyone who trusts the signing key*, and — because inputs and outputs are
//! by hash — the **output digests are reproducible**: a skeptic re-runs the same command over the same
//! inputs and confirms the same `stdout_sha256` / `inputs_root`. The signed body itself is *not*
//! reproducible (it carries a timestamp and a per-run key), so what a third party reproduces is the
//! deterministic outputs, not the `body_digest`. It is **not** a proof of honest execution against a
//! prover who forges the `bulla` binary *and* controls the host; that adversary needs the (optional,
//! future) hardware-TEE anchor. Everything short of that, a bulla covers with no special hardware and no root.
//!
//! `bulla-core` is deliberately platform-independent (pure Rust crypto + serde). The Linux isolation
//! mechanism lives in `hermit-core`; the CLI wires the two together.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "bulla-receipt/v0";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------------------------
// Policy — what the receipt commits to.
// ---------------------------------------------------------------------------------------------

/// Network posture the run demands. Phase 0 is deny-all vs allow-all; an audited allowlist comes later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No egress: a fresh empty network namespace (only loopback). The default.
    Deny,
    /// Host network shared into the cell (opt-in; changes the threat model).
    Allow,
}

/// The isolation contract a bulla attests. Serialized deterministically; its sha256 is `policy_digest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalPolicy {
    pub network: NetworkPolicy,
    /// Fixed env + no-ASLR + pinned clock: the determinism precondition for run-to-run comparison.
    pub deterministic: bool,
    /// Reduce the work dir's git repo to a single history-free HEAD before the run, so the fix
    /// cannot be mined from `.git` (Cursor's second retrieval vector). Only meaningful if `.git` exists.
    #[serde(default)]
    pub git_hygiene: bool,
    /// Hosts the cell may reach through the mediated egress broker (a Unix socket — the network
    /// namespace stays empty, so there is no *raw* egress; every call is allowlist-checked and hashed
    /// into the receipt). Empty = no egress at all. This is "smart egress": scoped, not open.
    #[serde(default)]
    pub egress_allow: Vec<String>,
    /// Wall-clock ceiling in milliseconds.
    pub wall_ms: u64,
}

impl Default for EvalPolicy {
    fn default() -> Self {
        Self {
            network: NetworkPolicy::Deny,
            deterministic: true,
            git_hygiene: false,
            egress_allow: Vec::new(),
            wall_ms: 60_000,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Building blocks.
// ---------------------------------------------------------------------------------------------

/// One input file, addressed by content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Content-addressed manifest of the work dir before the run. `root` is the Merkle-ish digest over entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Manifest {
    pub root: String,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    /// Build from (path, sha256, bytes) triples. Entries are sorted by path for a stable root.
    pub fn from_entries(mut files: Vec<FileEntry>) -> Self {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut h = Sha256::new();
        for f in &files {
            h.update(f.path.as_bytes());
            h.update([0]);
            h.update(f.sha256.as_bytes());
            h.update([0]);
            h.update(f.bytes.to_le_bytes());
        }
        Manifest {
            root: hex::encode(h.finalize()),
            files,
        }
    }
}

/// What the sandbox actually enforced — mirrors hermit-core's `Applied`, kept as plain data so
/// `bulla-core` stays platform-independent. The CLI fills this from the real run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppliedSummary {
    pub user_ns: bool,
    pub pid_ns: bool,
    pub mount_ns: bool,
    pub net_ns: bool,
    pub uts_ns: bool,
    pub ipc_ns: bool,
    pub cgroup_ns: bool,
    pub pivot_root: bool,
    pub no_new_privs: bool,
    pub no_aslr: bool,
    pub fixed_env: bool,
    pub seccomp: bool,
    pub loopback: bool,
    pub cgroup: String,
}

/// The result of the run, with outputs recorded by hash (not stored inline).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutcomeSummary {
    /// "code" | "signal" | "timeout" | "setup_failed"
    pub exit_kind: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub wall_ms: u64,
    pub stdout_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_sha256: String,
    pub stderr_bytes: u64,
}

/// One entry in the tamper-evident event chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub seq: u32,
    pub kind: String,
    pub detail: String,
    /// hash of the previous event (ZERO_HASH for the first).
    pub prev: String,
    /// sha256(prev ++ seq ++ kind ++ detail).
    pub hash: String,
}

#[derive(Serialize)]
struct EventCore<'a> {
    seq: u32,
    kind: &'a str,
    detail: &'a str,
    prev: &'a str,
}

/// Fill `prev`/`hash` for a chain of (seq, kind, detail) events and return the chain head.
pub fn seal_chain(raw: &[(u32, String, String)]) -> (Vec<Event>, String) {
    let mut prev = ZERO_HASH.to_string();
    let mut out = Vec::with_capacity(raw.len());
    for (seq, kind, detail) in raw {
        let core = EventCore {
            seq: *seq,
            kind,
            detail,
            prev: &prev,
        };
        let bytes = serde_json::to_vec(&core).expect("event core serializes");
        let hash = sha256_hex(&bytes);
        out.push(Event {
            seq: *seq,
            kind: kind.clone(),
            detail: detail.clone(),
            prev: prev.clone(),
            hash: hash.clone(),
        });
        prev = hash;
    }
    (out, prev)
}

// ---------------------------------------------------------------------------------------------
// The receipt body + signed envelope.
// ---------------------------------------------------------------------------------------------

/// The grading phase of a two-cell eval (`bulla eval`). Grading runs in a SEPARATE cell over a
/// controlled view: the trusted grader files + only the agent's edits to the declared solution
/// paths — so an agent that poisons the grader (a force-pass `conftest.py`, an overwritten test,
/// a trojanized binary) cannot reach the cell that scores it. `isolated=false` records the
/// vulnerable same-cell grading (RDI's 100%-break shape) honestly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GradeSummary {
    pub command: Vec<String>,
    /// Was grading isolated from agent tampering (separate cell + restored grader)?
    pub isolated: bool,
    /// Files the agent was allowed to change and that were carried into the grade cell.
    pub solution_paths: Vec<String>,
    /// Grader/oracle files, restored to their pre-solve trusted content before grading.
    pub grader_paths: Vec<String>,
    /// sha256 over the trusted grader files (sorted) — what grading actually ran against.
    pub grader_digest: String,
    pub outcome: OutcomeSummary,
}

/// What the egress broker logged for one outbound request the cell made through the mediated socket.
/// (The network namespace is empty; this is the *only* way out, and it is allowlist-checked.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoggedCall {
    pub host: String,
    pub port: u16,
    pub path: String,
    /// Was the (host, port) on the allowlist? A denied call is refused and recorded, not performed.
    pub allowed: bool,
    /// The IP the host actually resolved to (records the true target, so DNS rebinding is visible).
    #[serde(default)]
    pub resolved_ip: String,
    pub req_sha256: String,
    pub resp_sha256: String,
    pub resp_bytes: u64,
}

/// One mediated egress call, chained into a tamper-evident per-call log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressCall {
    pub seq: u32,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub allowed: bool,
    #[serde(default)]
    pub resolved_ip: String,
    pub req_sha256: String,
    pub resp_sha256: String,
    pub resp_bytes: u64,
    pub prev: String,
    pub hash: String,
}

/// The mediated-egress record folded into a receipt: the signed allowlist and a hash-chained log of
/// every request/response that crossed the broker. `seal_ok` stays true (the netns is still empty —
/// no raw egress); this makes the *scope* of egress auditable rather than invisible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressSummary {
    pub allowlist: Vec<String>,
    pub allowlist_digest: String,
    pub calls: Vec<EgressCall>,
    pub log_head: String,
}

/// Build the egress summary: digest the sorted allowlist and chain the logged calls.
pub fn egress_summary(allowlist: &[String], calls: &[LoggedCall]) -> EgressSummary {
    let mut al: Vec<String> = allowlist.to_vec();
    al.sort();
    al.dedup();
    let allowlist_digest = sha256_hex(al.join("\n").as_bytes());

    #[derive(Serialize)]
    struct Core<'a> {
        seq: u32,
        host: &'a str,
        port: u16,
        path: &'a str,
        allowed: bool,
        resolved_ip: &'a str,
        req_sha256: &'a str,
        resp_sha256: &'a str,
        resp_bytes: u64,
        prev: &'a str,
    }
    let mut prev = ZERO_HASH.to_string();
    let mut out = Vec::with_capacity(calls.len());
    for (i, c) in calls.iter().enumerate() {
        let core = Core {
            seq: i as u32,
            host: &c.host,
            port: c.port,
            path: &c.path,
            allowed: c.allowed,
            resolved_ip: &c.resolved_ip,
            req_sha256: &c.req_sha256,
            resp_sha256: &c.resp_sha256,
            resp_bytes: c.resp_bytes,
            prev: &prev,
        };
        let hash = sha256_hex(&serde_json::to_vec(&core).expect("egress core serializes"));
        out.push(EgressCall {
            seq: i as u32,
            host: c.host.clone(),
            port: c.port,
            path: c.path.clone(),
            allowed: c.allowed,
            resolved_ip: c.resolved_ip.clone(),
            req_sha256: c.req_sha256.clone(),
            resp_sha256: c.resp_sha256.clone(),
            resp_bytes: c.resp_bytes,
            prev: prev.clone(),
            hash: hash.clone(),
        });
        prev = hash;
    }
    EgressSummary {
        allowlist: al,
        allowlist_digest,
        calls: out,
        log_head: prev,
    }
}

/// Everything a bulla attests, minus the signature. The signature covers the canonical bytes of this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptBody {
    pub schema: String,
    pub created_epoch: u64,
    pub command: Vec<String>,
    pub work_dir: String,
    pub policy: EvalPolicy,
    pub policy_digest: String,
    pub inputs: Manifest,
    pub applied: AppliedSummary,
    /// The solve-phase outcome (the only outcome for a plain `bulla run`).
    pub outcome: OutcomeSummary,
    /// Present for `bulla eval`: the separate grading phase and whether its oracle was isolated.
    #[serde(default)]
    pub grade: Option<GradeSummary>,
    /// Present when the run used mediated egress: the signed allowlist + a hash-chained log of every
    /// request/response that crossed the broker socket.
    #[serde(default)]
    pub egress: Option<EgressSummary>,
    /// git state of the work dir: `None` = not a git repo; `Some(true)` = bulla pruned it to a
    /// history-free HEAD; `Some(false)` = a repo with history was present and NOT sealed (mineable).
    #[serde(default)]
    pub git_sealed: Option<bool>,
    /// HEAD sha after sealing (or the observed HEAD when a repo was present).
    #[serde(default)]
    pub git_head: Option<String>,
    /// The run-ledger head *before* this run (chains this attempt onto every prior one in the work
    /// dir). A lucky pass reported as pass@1 can't hide the attempts before it: its `ledger_prev`
    /// links back through them. `None`/ZERO means this was the first recorded attempt.
    #[serde(default)]
    pub ledger_prev: Option<String>,
    /// Did the *applied* isolation satisfy the *demanded* policy? The honest verdict.
    pub seal_ok: bool,
    /// Human-readable reasons a seal was NOT satisfied (empty when seal_ok).
    pub seal_notes: Vec<String>,
    pub events: Vec<Event>,
    pub chain_head: String,
}

impl ReceiptBody {
    /// Canonical bytes the digest and signature are computed over.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("receipt body serializes")
    }
    pub fn digest_hex(&self) -> String {
        sha256_hex(&self.canonical())
    }
}

/// Did a **hermetic seal** hold? Returns (ok, notes). A hermetic seal is the strong claim bulla
/// exists to make: no egress, private root, core namespaces, and (when demanded) a deterministic
/// profile. It is deliberately independent of `policy.network`: an opt-in `--allow-net` run is
/// *not* hermetically sealed even though it complied with a permissive policy — and the receipt
/// says so plainly, so a score produced with the network on can never masquerade as a sealed one.
pub fn evaluate_seal(
    policy: &EvalPolicy,
    applied: &AppliedSummary,
    git_sealed: Option<bool>,
    oracle_isolated: Option<bool>,
) -> (bool, Vec<String>) {
    let mut notes = Vec::new();
    if !applied.net_ns {
        notes.push("network was not isolated (egress possible) — not hermetically sealed".into());
    }
    if !applied.user_ns || !applied.pid_ns || !applied.mount_ns {
        notes.push("core namespaces (user/pid/mount) were not all applied".into());
    }
    if !applied.pivot_root {
        notes.push("root was not pivoted into a private mount".into());
    }
    if policy.deterministic && !applied.no_aslr {
        notes.push("ASLR was not disabled — addresses are nondeterministic".into());
    }
    if policy.deterministic && !applied.fixed_env {
        notes
            .push("fixed-env profile was not applied — the environment is nondeterministic".into());
    }
    if git_sealed == Some(false) {
        notes.push(
            "git history is present and unsealed — the fix may be mineable from .git (use --seal-git)"
                .into(),
        );
    }
    if oracle_isolated == Some(false) {
        notes.push(
            "grading ran in the same cell as the solve — the oracle is tamperable (use bulla eval)"
                .into(),
        );
    }
    (notes.is_empty(), notes)
}

/// A signed bulla: the body, its digest, the signer's public key, and the Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedReceipt {
    pub body: ReceiptBody,
    pub body_digest: String,
    pub pubkey: String,
    pub sig: String,
}

/// Report from verifying a bulla.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub sig_ok: bool,
    pub digest_ok: bool,
    pub chain_ok: bool,
    pub seal_ok: bool,
    pub notes: Vec<String>,
}
impl VerifyReport {
    /// The receipt is intact (unforged + internally consistent). Note: intact != seal_ok; a valid
    /// bulla can faithfully attest that the seal did NOT hold.
    pub fn intact(&self) -> bool {
        self.sig_ok && self.digest_ok && self.chain_ok
    }
}

// ---------------------------------------------------------------------------------------------
// Run ledger — a tamper-evident append-only chain of attempts (anti-cherry-pick / honest pass@k).
// ---------------------------------------------------------------------------------------------

/// One recorded attempt. Entries chain by `prev`; dropping or reordering any attempt breaks the
/// chain, so a lucky pass cannot be shown without the failures that preceded it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    pub seq: u32,
    pub receipt_digest: String,
    pub seal_ok: bool,
    pub solve_exit: Option<i32>,
    pub grade_exit: Option<i32>,
    pub prev: String,
    pub hash: String,
}

/// Build the next ledger entry (computing its hash) given the current chain head.
pub fn ledger_entry(
    prev: &str,
    seq: u32,
    receipt_digest: &str,
    seal_ok: bool,
    solve_exit: Option<i32>,
    grade_exit: Option<i32>,
) -> LedgerEntry {
    #[derive(Serialize)]
    struct Core<'a> {
        prev: &'a str,
        seq: u32,
        receipt_digest: &'a str,
        seal_ok: bool,
        solve_exit: Option<i32>,
        grade_exit: Option<i32>,
    }
    let core = Core {
        prev,
        seq,
        receipt_digest,
        seal_ok,
        solve_exit,
        grade_exit,
    };
    let hash = sha256_hex(&serde_json::to_vec(&core).expect("ledger core serializes"));
    LedgerEntry {
        seq,
        receipt_digest: receipt_digest.to_string(),
        seal_ok,
        solve_exit,
        grade_exit,
        prev: prev.to_string(),
        hash,
    }
}

#[derive(Debug, Clone)]
pub struct LedgerReport {
    pub chain_ok: bool,
    /// seq of the first entry that failed to recompute (dropped / reordered / edited).
    pub break_at: Option<u32>,
    pub attempts: u32,
    /// Attempts whose effective outcome (grade if present, else solve) exited 0.
    pub passes: u32,
    pub seal_held: u32,
}

/// Recompute the whole ledger chain and tally attempts vs passes. `chain_ok=false` means an attempt
/// was dropped, reordered, or edited — the pass rate on a broken ledger cannot be trusted.
pub fn verify_ledger(entries: &[LedgerEntry]) -> LedgerReport {
    let mut prev = ZERO_HASH.to_string();
    let mut chain_ok = true;
    let mut break_at = None;
    let (mut passes, mut seal_held) = (0u32, 0u32);
    for (i, e) in entries.iter().enumerate() {
        let recomputed = ledger_entry(
            &prev,
            e.seq,
            &e.receipt_digest,
            e.seal_ok,
            e.solve_exit,
            e.grade_exit,
        );
        if e.seq != i as u32 || e.prev != prev || e.hash != recomputed.hash {
            chain_ok = false;
            break_at.get_or_insert(e.seq);
        }
        if e.grade_exit.or(e.solve_exit) == Some(0) {
            passes += 1;
        }
        if e.seal_ok {
            seal_held += 1;
        }
        prev = e.hash.clone();
    }
    LedgerReport {
        chain_ok,
        break_at,
        attempts: entries.len() as u32,
        passes,
        seal_held,
    }
}

// ---------------------------------------------------------------------------------------------
// Crypto.
// ---------------------------------------------------------------------------------------------

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// 32 fresh random bytes for a new Ed25519 signing seed.
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("os rng");
    seed
}

/// Hex-encode a 32-byte seed (for persisting a key file).
pub fn seed_to_hex(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}

/// Parse a 32-byte seed from 64 hex chars, if valid.
pub fn seed_from_hex(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

/// Derive the hex Ed25519 public key for a signing seed.
pub fn pubkey_hex(seed: &[u8; 32]) -> String {
    use ed25519_dalek::SigningKey;
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Ed25519-sign an arbitrary message with a seed; returns the hex signature. (Used by the TEE-tier
/// attestation flow to bind a receipt digest to an enclave-resident key.)
pub fn sign_message(seed: &[u8; 32], msg: &[u8]) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    hex::encode(SigningKey::from_bytes(seed).sign(msg).to_bytes())
}

/// Sign a receipt body with the given 32-byte Ed25519 seed.
pub fn sign(body: ReceiptBody, seed: &[u8; 32]) -> SignedReceipt {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(seed);
    let vk = sk.verifying_key();
    let canonical = body.canonical();
    let sig = sk.sign(&canonical);
    SignedReceipt {
        body_digest: sha256_hex(&canonical),
        pubkey: hex::encode(vk.to_bytes()),
        sig: hex::encode(sig.to_bytes()),
        body,
    }
}

/// Verify a bulla: signature, digest field, and event chain, plus surface the attested seal verdict.
pub fn verify(sr: &SignedReceipt) -> VerifyReport {
    use ed25519_dalek::{Signature, VerifyingKey};
    let mut notes = Vec::new();
    let canonical = sr.body.canonical();

    let digest_ok = sha256_hex(&canonical) == sr.body_digest;
    if !digest_ok {
        notes.push("body_digest does not match the receipt body".into());
    }

    // signature
    let sig_ok = (|| -> bool {
        let pk = match hex::decode(&sr.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            Some(a) => a,
            None => {
                notes.push("public key is not 32 hex bytes".into());
                return false;
            }
        };
        let vk = match VerifyingKey::from_bytes(&pk) {
            Ok(v) => v,
            Err(_) => {
                notes.push("public key is not a valid Ed25519 point".into());
                return false;
            }
        };
        let sig_arr = match hex::decode(&sr.sig)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
        {
            Some(a) => a,
            None => {
                notes.push("signature is not 64 hex bytes".into());
                return false;
            }
        };
        let sig = Signature::from_bytes(&sig_arr);
        match vk.verify_strict(&canonical, &sig) {
            Ok(()) => true,
            Err(_) => {
                notes.push("Ed25519 signature does not verify against the body".into());
                false
            }
        }
    })();

    // event chain
    let raw: Vec<(u32, String, String)> = sr
        .body
        .events
        .iter()
        .map(|e| (e.seq, e.kind.clone(), e.detail.clone()))
        .collect();
    let (recomputed, head) = seal_chain(&raw);
    let chain_ok = recomputed == sr.body.events && head == sr.body.chain_head;
    if !chain_ok {
        notes.push("event hash-chain does not recompute (log was altered)".into());
    }

    // seal verdict (recomputed from the attested policy + applied, independent of the stored bool)
    let (seal_ok, seal_notes) = evaluate_seal(
        &sr.body.policy,
        &sr.body.applied,
        sr.body.git_sealed,
        sr.body.grade.as_ref().map(|g| g.isolated),
    );
    if seal_ok != sr.body.seal_ok {
        notes.push("stored seal_ok disagrees with recomputed seal verdict".into());
    }
    notes.extend(seal_notes);

    VerifyReport {
        sig_ok,
        digest_ok,
        chain_ok,
        seal_ok,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> ReceiptBody {
        let policy = EvalPolicy::default();
        let policy_digest = sha256_hex(&serde_json::to_vec(&policy).unwrap());
        let applied = AppliedSummary {
            user_ns: true,
            pid_ns: true,
            mount_ns: true,
            net_ns: true,
            uts_ns: true,
            ipc_ns: true,
            cgroup_ns: true,
            pivot_root: true,
            no_new_privs: true,
            no_aslr: true,
            fixed_env: true,
            seccomp: true,
            loopback: true,
            cgroup: "n/a".into(),
        };
        let (seal_ok, seal_notes) = evaluate_seal(&policy, &applied, None, None);
        let (events, chain_head) = seal_chain(&[
            (0, "start".into(), "argv=echo hi".into()),
            (1, "seal_applied".into(), "net_ns=true".into()),
            (2, "outcome".into(), "exit=0".into()),
        ]);
        ReceiptBody {
            schema: SCHEMA.into(),
            created_epoch: 1_700_000_000,
            command: vec!["echo".into(), "hi".into()],
            work_dir: "/work".into(),
            policy,
            policy_digest,
            inputs: Manifest::from_entries(vec![FileEntry {
                path: "a.txt".into(),
                sha256: sha256_hex(b"a"),
                bytes: 1,
            }]),
            applied,
            outcome: OutcomeSummary {
                exit_kind: "code".into(),
                exit_code: Some(0),
                signal: None,
                wall_ms: 3,
                stdout_sha256: sha256_hex(b"hi\n"),
                stdout_bytes: 3,
                stderr_sha256: sha256_hex(b""),
                stderr_bytes: 0,
            },
            grade: None,
            egress: None,
            git_sealed: None,
            git_head: None,
            ledger_prev: None,
            seal_ok,
            seal_notes,
            events,
            chain_head,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let seed = generate_seed();
        let sr = sign(sample_body(), &seed);
        let r = verify(&sr);
        assert!(r.intact(), "fresh receipt must be intact: {:?}", r.notes);
        assert!(r.seal_ok, "fully-isolated sample must pass the seal");
    }

    #[test]
    fn tampering_the_body_breaks_the_signature() {
        let seed = generate_seed();
        let mut sr = sign(sample_body(), &seed);
        sr.body.outcome.exit_code = Some(0).map(|_| 42); // flip the reported exit code
        let r = verify(&sr);
        assert!(!r.intact(), "a mutated body must fail verification");
    }

    #[test]
    fn tampering_an_event_breaks_the_chain() {
        let seed = generate_seed();
        let mut sr = sign(sample_body(), &seed);
        sr.body.events[1].detail = "net_ns=false".into();
        let r = verify(&sr);
        assert!(!r.chain_ok, "editing the log must break the hash-chain");
    }

    #[test]
    fn missing_net_ns_fails_the_seal_but_stays_intact() {
        let seed = generate_seed();
        let mut body = sample_body();
        body.applied.net_ns = false;
        let (ok, notes) = evaluate_seal(&body.policy, &body.applied, body.git_sealed, None);
        body.seal_ok = ok;
        body.seal_notes = notes;
        let sr = sign(body, &seed);
        let r = verify(&sr);
        assert!(r.intact(), "receipt is still a valid, unforged record");
        assert!(!r.seal_ok, "but it honestly attests the seal did not hold");
    }

    #[test]
    fn unsealed_git_fails_the_seal() {
        let seed = generate_seed();
        let mut body = sample_body();
        body.git_sealed = Some(false); // a repo with history was present and not pruned
        let (ok, notes) = evaluate_seal(&body.policy, &body.applied, body.git_sealed, None);
        body.seal_ok = ok;
        body.seal_notes = notes;
        let sr = sign(body, &seed);
        let r = verify(&sr);
        assert!(r.intact());
        assert!(
            !r.seal_ok,
            "an unsealed git repo must fail the hermetic seal"
        );
    }

    #[test]
    fn same_cell_grading_fails_the_seal() {
        let policy = EvalPolicy::default();
        let applied = AppliedSummary {
            user_ns: true,
            pid_ns: true,
            mount_ns: true,
            net_ns: true,
            pivot_root: true,
            no_aslr: true,
            fixed_env: true,
            ..Default::default()
        };
        // A grading phase that was NOT isolated (RDI's same-cell oracle) must fail the seal.
        let (ok, notes) = evaluate_seal(&policy, &applied, None, Some(false));
        assert!(!ok, "same-cell grading must fail the hermetic seal");
        assert!(notes.iter().any(|n| n.contains("oracle is tamperable")));
        // An isolated grade cell over otherwise-hermetic isolation passes.
        let (ok2, _) = evaluate_seal(&policy, &applied, None, Some(true));
        assert!(ok2, "an isolated grade cell must pass");
    }

    #[test]
    fn ledger_chain_detects_a_dropped_attempt() {
        // Five attempts, 1 pass; chain them.
        let exits = [1, 1, 0, 1, 1];
        let mut prev = ZERO_HASH.to_string();
        let mut entries = Vec::new();
        for (i, ex) in exits.iter().enumerate() {
            let e = ledger_entry(&prev, i as u32, &format!("rcpt{i}"), true, Some(*ex), None);
            prev = e.hash.clone();
            entries.push(e);
        }
        let r = verify_ledger(&entries);
        assert!(r.chain_ok && r.attempts == 5 && r.passes == 1);
        // Cherry-pick: drop attempt #1 (a failure) to inflate the pass rate.
        let mut tampered = entries.clone();
        tampered.remove(1);
        let r2 = verify_ledger(&tampered);
        assert!(
            !r2.chain_ok,
            "dropping an attempt must break the ledger chain"
        );
    }

    #[test]
    fn egress_log_chains_and_digests_the_allowlist() {
        let allow = vec!["api.example.com".to_string(), "127.0.0.1".to_string()];
        let calls = vec![
            LoggedCall {
                host: "127.0.0.1".into(),
                port: 8080,
                path: "/quote".into(),
                allowed: true,
                resolved_ip: "127.0.0.1".into(),
                req_sha256: sha256_hex(b"GET /quote"),
                resp_sha256: sha256_hex(b"{}"),
                resp_bytes: 2,
            },
            LoggedCall {
                host: "evil.example".into(),
                port: 443,
                path: "/x".into(),
                allowed: false,
                resolved_ip: String::new(),
                req_sha256: sha256_hex(b"GET /x"),
                resp_sha256: sha256_hex(b""),
                resp_bytes: 0,
            },
        ];
        let e = egress_summary(&allow, &calls);
        assert_eq!(e.calls.len(), 2);
        assert_eq!(e.calls[0].prev, ZERO_HASH);
        assert_eq!(e.calls[1].prev, e.calls[0].hash); // chained
        assert_eq!(e.log_head, e.calls[1].hash);
        assert!(
            !e.calls[1].allowed,
            "the off-allowlist call is recorded as denied"
        );
        // allowlist digest is order-independent (sorted + deduped)
        let e2 = egress_summary(
            &["127.0.0.1".to_string(), "api.example.com".to_string()],
            &calls,
        );
        assert_eq!(e.allowlist_digest, e2.allowlist_digest);
    }
}
