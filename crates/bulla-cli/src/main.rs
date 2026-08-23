//! bulla — run a command inside a hermetic cell and emit a signed receipt (a *bulla*) that the
//! isolation seal held; verify one offline with `bulla verify`.
//!
//! This is the Phase-0 spike: it wires the real `hermit-core` sandbox to the `bulla-core` receipt
//! model. `bulla run` produces a signed record binding the enforced policy (network off, deterministic
//! env) to the outcome, by hash; `bulla verify` re-checks the signature, the digest, the event chain,
//! and the seal verdict — with no network and no trust in the runner beyond its signing key.

use std::fs;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use bulla_core as bc;
use hermit_core as hc;

#[derive(Parser)]
#[command(
    name = "bulla",
    version,
    about = "Hermetic eval cell + a signed receipt that the seal held"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command in a sealed cell and write a signed receipt.
    Run(RunArgs),
    /// Solve then grade in TWO cells: grading runs over a restored view (trusted grader + only the
    /// agent's solution edits), so a poisoned oracle can't reach the cell that scores it.
    Eval(EvalArgs),
    /// Verify a receipt offline: signature, digest, event chain, and seal verdict.
    Verify(VerifyArgs),
    /// Verify a run ledger and report the honest pass rate (dropping an attempt breaks the chain).
    Log(LogArgs),
    /// Print the public key for a signing seed (creating it if absent).
    Keygen(KeygenArgs),
    /// TEE tier: detect a hardware enclave (SEV-SNP / TDX / SGX / Nitro) and, with --simulate,
    /// demonstrate the attestation flow that binds a receipt digest to an enclave-resident key.
    Attest(AttestArgs),
    /// Internal: the mediated-egress broker (spawned by `run --egress-allow`). Not for direct use.
    #[command(hide = true)]
    EgressBroker(BrokerArgs),
}

#[derive(Parser)]
struct RunArgs {
    /// Work dir bound read-write at /work inside the cell; also the cwd and the input set.
    #[arg(long, default_value = ".")]
    work: PathBuf,
    /// Where to write the signed receipt (default: a host-only per-work-dir state dir; a path planted
    /// as a symlink is unlinked before writing).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Ed25519 signing seed file (32 raw/hex bytes). Default: a HOST-ONLY per-work-dir state dir
    /// (never inside /work, so sandboxed code can't steal or plant it). Refused if inside the work dir.
    #[arg(long)]
    key: Option<PathBuf>,
    /// Allow host network into the cell (opt-in; changes the threat model). Default: deny.
    #[arg(long)]
    allow_net: bool,
    /// Drop the deterministic profile (ASLR on, inherited env). Default: deterministic.
    #[arg(long)]
    nondeterministic: bool,
    /// If the sandbox cannot be built, run the command UNCONFINED on the host instead of refusing.
    /// Off by default (fail-closed): without isolation, bulla will not run untrusted code.
    #[arg(long)]
    allow_no_sandbox: bool,
    /// Reduce the work dir's git repo to a single history-free HEAD before the run, so the fix
    /// can't be mined from `.git`. DESTRUCTIVE to `.git` — give bulla a disposable checkout.
    #[arg(long)]
    seal_git: bool,
    /// Wall-clock ceiling in milliseconds.
    #[arg(long, default_value_t = 60_000)]
    wall_ms: u64,
    /// Append this attempt to a tamper-evident run ledger (default: a host-only per-work-dir state dir).
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Emit a compact machine-readable JSON summary to stdout instead of the human table.
    #[arg(long)]
    json: bool,
    /// Smart egress: allow the cell to reach `HOST` or `HOST:PORT` through the mediated broker socket
    /// (repeatable). A bare host permits only ports 80/443; internal IPs are blocked unless allowlisted
    /// as a literal address. The netns stays empty (no raw egress); every call is hashed into the receipt.
    #[arg(long = "egress-allow", value_name = "HOST[:PORT]")]
    egress_allow: Vec<String>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Parser)]
struct EvalArgs {
    /// Work dir (the disposable checkout). The solve phase mutates it.
    #[arg(long, default_value = ".")]
    work: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    /// Allow host network into both cells (opt-in). Default: deny.
    #[arg(long)]
    allow_net: bool,
    #[arg(long)]
    nondeterministic: bool,
    /// If the sandbox cannot be built, run UNCONFINED on the host instead of refusing (fail-closed default).
    #[arg(long)]
    allow_no_sandbox: bool,
    /// Seal the work dir's git history before the solve.
    #[arg(long)]
    seal_git: bool,
    #[arg(long, default_value_t = 60_000)]
    wall_ms: u64,
    /// A file the agent may change and that is carried into the grade cell (repeatable).
    #[arg(long = "solution", value_name = "PATH")]
    solution: Vec<String>,
    /// A grader/oracle file, restored to its trusted pre-solve content before grading (repeatable).
    #[arg(long = "grader", value_name = "PATH")]
    grader: Vec<String>,
    /// Grade in the SAME post-solve dir (vulnerable, RDI-style) instead of an isolated grade cell.
    #[arg(long)]
    no_grade_isolation: bool,
    /// Shell command for the solve phase (the "agent").
    #[arg(long)]
    solve: String,
    /// Shell command for the grade phase (the oracle).
    #[arg(long)]
    grade: String,
    /// Append this attempt to a tamper-evident run ledger (default: a host-only per-work-dir state dir).
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Emit a compact machine-readable JSON summary to stdout instead of the human table.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to a receipt.json.
    receipt: PathBuf,
    /// Print the full attested body as JSON.
    #[arg(long)]
    show: bool,
    /// Emit a compact machine-readable JSON verdict to stdout instead of the human table.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct LogArgs {
    /// Path to a ledger.jsonl.
    ledger: PathBuf,
}

#[derive(Parser)]
struct AttestArgs {
    /// Bind this receipt's body digest into the attestation's report-data (the enclave "endorses" it).
    #[arg(long)]
    receipt: Option<PathBuf>,
    /// Emit a CLEARLY-LABELLED SIMULATED attestation (no hardware). For demonstrating the flow only.
    #[arg(long)]
    simulate: bool,
    /// JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct BrokerArgs {
    #[arg(long)]
    sock: PathBuf,
    #[arg(long)]
    log: PathBuf,
    #[arg(long = "allow")]
    allow: Vec<String>,
}

#[derive(Parser)]
struct KeygenArgs {
    #[arg(long, default_value = ".bulla/ed25519.seed")]
    key: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run(a) => cmd_run(a),
        Cmd::Eval(a) => cmd_eval(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::Log(a) => cmd_log(a),
        Cmd::Attest(a) => cmd_attest(a),
        Cmd::EgressBroker(a) => cmd_egress_broker(a),
        Cmd::Keygen(a) => {
            let seed = load_or_create_seed(&a.key)?;
            println!(
                "pubkey {}\nseed   {}",
                bc::pubkey_hex(&seed),
                a.key.display()
            );
            Ok(())
        }
    }
}

// ------------------------------------------------------------------------------------------------

fn cmd_run(a: RunArgs) -> Result<()> {
    let work = a
        .work
        .canonicalize()
        .with_context(|| format!("work dir not found: {}", a.work.display()))?;
    if !work.is_dir() {
        bail!("work dir is not a directory: {}", work.display());
    }

    // Trust material (signing key + ledger) MUST live outside the cell-writable /work mount, and the
    // key MUST be loaded before any untrusted code runs — otherwise the sandboxed process could plant
    // or steal it (security finding C1). Default them into a host-only per-work-dir state directory.
    let state = state_dir(&work)?;
    let key_path = a.key.clone().unwrap_or_else(|| state.join("ed25519.seed"));
    let ledger_path = a
        .ledger
        .clone()
        .unwrap_or_else(|| state.join("ledger.jsonl"));
    reject_inside_work(&key_path, &work, "--key")?;
    reject_inside_work(&ledger_path, &work, "--ledger")?;
    let seed = load_or_create_seed(&key_path)?; // loaded BEFORE the cell; held only in parent memory

    let policy = bc::EvalPolicy {
        network: if a.allow_net {
            bc::NetworkPolicy::Allow
        } else {
            bc::NetworkPolicy::Deny
        },
        deterministic: !a.nondeterministic,
        git_hygiene: a.seal_git,
        egress_allow: a.egress_allow.clone(),
        wall_ms: a.wall_ms,
    };
    let policy_digest = bc::sha256_hex(&serde_json::to_vec(&policy)?);

    // 1. git-hygiene preflight (before hashing/running): seal `.git` to a history-free HEAD, or
    //    record that a repo with history is present and unsealed (mineable).
    let (git_sealed, git_head) = seal_git(&work, a.seal_git)?;

    // 2. Content-address the inputs (the working tree; `.git` is excluded).
    let inputs = hash_work_dir(&work)?;

    // 2b. Smart egress: if hosts are allowlisted, start the mediated broker BEFORE the cell (as a
    //     separate process, to keep this process single-threaded for hermit-core's clone).
    let egress_broker = if policy.egress_allow.is_empty() {
        None
    } else {
        Some(start_egress_broker(&work, &state, &policy.egress_allow)?)
    };

    // 3. Run the command in the real hermetic cell.
    let cell = run_in_cell(
        &a.command,
        &work,
        &policy.network,
        policy.deterministic,
        policy.wall_ms,
        a.allow_no_sandbox,
    )?;
    let outcome = cell.outcome;
    let applied = cell.applied;
    let outcome_sum = cell.summary;
    let (seal_ok, mut seal_notes) = bc::evaluate_seal(&policy, &applied, git_sealed, None);
    if let Some(n) = cell.note {
        seal_notes.push(n);
    }

    // 3b. Stop the broker and fold its allowlist + hash-chained call log into the receipt.
    let egress = match egress_broker {
        Some((child, log)) => Some(collect_egress(child, &log, &policy.egress_allow)),
        None => None,
    };

    // 4. Hash-chained event log.
    let raw_events = vec![
        (
            0u32,
            "start".to_string(),
            format!("argv={}", a.command.join(" ")),
        ),
        (
            1,
            "inputs_hashed".into(),
            format!("root={} files={}", short(&inputs.root), inputs.files.len()),
        ),
        (
            2,
            "seal_applied".into(),
            format!(
                "net_ns={} user_ns={} pivot_root={} seccomp={} no_aslr={} fixed_env={} git_sealed={:?}",
                applied.net_ns,
                applied.user_ns,
                applied.pivot_root,
                applied.seccomp,
                applied.no_aslr,
                applied.fixed_env,
                git_sealed
            ),
        ),
        (3, "exec".into(), format!("wall_ms={}", outcome.wall_ms)),
        (
            4,
            "outcome".into(),
            format!(
                "{} out={} err={}",
                outcome_sum.exit_kind,
                short(&outcome_sum.stdout_sha256),
                short(&outcome_sum.stderr_sha256)
            ),
        ),
    ];
    let (events, chain_head) = bc::seal_chain(&raw_events);

    // 5. Chain this attempt onto the run ledger (host-only path; resolved above).
    let (ledger_prev, ledger_seq) = ledger_head(&ledger_path)?;
    let solve_exit = outcome_sum.exit_code;

    let body = bc::ReceiptBody {
        schema: bc::SCHEMA.into(),
        created_epoch: now_epoch(),
        command: a.command.clone(),
        work_dir: work.display().to_string(),
        policy,
        policy_digest,
        inputs,
        applied,
        outcome: outcome_sum,
        grade: None,
        egress,
        git_sealed,
        git_head,
        ledger_prev: Some(ledger_prev.clone()),
        seal_ok,
        seal_notes,
        events,
        chain_head,
    };

    // 6. Sign (with the pre-loaded key), write the receipt, and append the ledger entry.
    let signed = bc::sign(body, &seed);

    // Default the receipt to the host-only state dir; unlink any pre-existing path first so in-cell
    // code can't plant a symlink at --out to redirect the write onto a host file (finding N1).
    let out_path = a.out.unwrap_or_else(|| state.join("receipt.json"));
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::remove_file(&out_path).ok();
    fs::write(&out_path, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("writing receipt to {}", out_path.display()))?;
    ledger_append(
        &ledger_path,
        &bc::ledger_entry(
            &ledger_prev,
            ledger_seq,
            &signed.body_digest,
            seal_ok,
            solve_exit,
            None,
        ),
    )?;

    if a.json {
        print_run_json(&signed, &out_path)?;
    } else {
        print_run_summary(&signed, &out_path);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------

fn cmd_eval(a: EvalArgs) -> Result<()> {
    let work = a
        .work
        .canonicalize()
        .with_context(|| format!("work dir not found: {}", a.work.display()))?;
    if !work.is_dir() {
        bail!("work dir is not a directory: {}", work.display());
    }

    // Trust material outside the cell-writable mount, key loaded before the cell (finding C1).
    let state = state_dir(&work)?;
    let key_path = a.key.clone().unwrap_or_else(|| state.join("ed25519.seed"));
    let ledger_path = a
        .ledger
        .clone()
        .unwrap_or_else(|| state.join("ledger.jsonl"));
    reject_inside_work(&key_path, &work, "--key")?;
    reject_inside_work(&ledger_path, &work, "--ledger")?;
    let seed = load_or_create_seed(&key_path)?;

    let policy = bc::EvalPolicy {
        network: if a.allow_net {
            bc::NetworkPolicy::Allow
        } else {
            bc::NetworkPolicy::Deny
        },
        deterministic: !a.nondeterministic,
        git_hygiene: a.seal_git,
        egress_allow: Vec::new(),
        wall_ms: a.wall_ms,
    };
    let policy_digest = bc::sha256_hex(&serde_json::to_vec(&policy)?);
    let (git_sealed, git_head) = seal_git(&work, a.seal_git)?;

    // Trusted snapshot of the pre-solve work dir (bytes, for restore + the input manifest).
    let trusted = snapshot_dir(&work)?;
    let inputs = manifest_from_snapshot(&trusted);
    let grader_digest = digest_paths(&trusted, &a.grader);

    // Phase 1: SOLVE — the agent edits the work dir freely.
    let solve = run_in_cell(
        &["sh".into(), "-c".into(), a.solve.clone()],
        &work,
        &policy.network,
        policy.deterministic,
        policy.wall_ms,
        a.allow_no_sandbox,
    )?;

    // Phase 2: build the grade view (trusted grader + only the agent's solution edits), then GRADE
    // in a fresh cell. --no-grade-isolation instead grades in the tampered post-solve dir.
    let isolated = !a.no_grade_isolation;
    let grade_view = if isolated {
        Some(build_grade_view(&trusted, &work, &a.solution)?)
    } else {
        None
    };
    let grade_work: &Path = grade_view.as_deref().unwrap_or(work.as_path());
    let grade = run_in_cell(
        &["sh".into(), "-c".into(), a.grade.clone()],
        grade_work,
        &policy.network,
        policy.deterministic,
        policy.wall_ms,
        a.allow_no_sandbox,
    )?;

    let applied = solve.applied.clone();
    let (seal_ok, mut seal_notes) =
        bc::evaluate_seal(&policy, &applied, git_sealed, Some(isolated));
    for n in [solve.note.clone(), grade.note.clone()]
        .into_iter()
        .flatten()
    {
        seal_notes.push(n);
    }

    let raw_events = vec![
        (
            0u32,
            "start".into(),
            format!("eval solve={:?} grade={:?}", a.solve, a.grade),
        ),
        (
            1,
            "inputs_hashed".into(),
            format!("root={} files={}", short(&inputs.root), inputs.files.len()),
        ),
        (
            2,
            "seal_applied".into(),
            format!(
                "net_ns={} pivot_root={} git_sealed={:?}",
                applied.net_ns, applied.pivot_root, git_sealed
            ),
        ),
        (
            3,
            "solve".into(),
            format!(
                "{} out={}",
                solve.summary.exit_kind,
                short(&solve.summary.stdout_sha256)
            ),
        ),
        (
            4,
            "grade_view".into(),
            format!(
                "isolated={isolated} grader_digest={}",
                short(&grader_digest)
            ),
        ),
        (
            5,
            "grade".into(),
            format!(
                "{} exit={:?}",
                grade.summary.exit_kind, grade.summary.exit_code
            ),
        ),
    ];
    let (events, chain_head) = bc::seal_chain(&raw_events);

    let grade_sum = bc::GradeSummary {
        command: vec!["sh".into(), "-c".into(), a.grade.clone()],
        isolated,
        solution_paths: a.solution.clone(),
        grader_paths: a.grader.clone(),
        grader_digest,
        outcome: grade.summary.clone(),
    };

    let (ledger_prev, ledger_seq) = ledger_head(&ledger_path)?;
    let solve_exit = solve.summary.exit_code;
    let grade_exit = grade.summary.exit_code;

    let body = bc::ReceiptBody {
        schema: bc::SCHEMA.into(),
        created_epoch: now_epoch(),
        command: vec!["sh".into(), "-c".into(), a.solve.clone()],
        work_dir: work.display().to_string(),
        policy,
        policy_digest,
        inputs,
        applied,
        outcome: solve.summary.clone(),
        grade: Some(grade_sum),
        egress: None,
        git_sealed,
        git_head,
        ledger_prev: Some(ledger_prev.clone()),
        seal_ok,
        seal_notes,
        events,
        chain_head,
    };

    let signed = bc::sign(body, &seed);
    // Host-only default + unlink-before-write to defeat a symlink planted at --out (finding N1).
    let out_path = a.out.unwrap_or_else(|| state.join("receipt.json"));
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::remove_file(&out_path).ok();
    fs::write(&out_path, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("writing receipt to {}", out_path.display()))?;
    ledger_append(
        &ledger_path,
        &bc::ledger_entry(
            &ledger_prev,
            ledger_seq,
            &signed.body_digest,
            seal_ok,
            solve_exit,
            grade_exit,
        ),
    )?;

    if let Some(gv) = grade_view {
        fs::remove_dir_all(gv).ok();
    }

    if a.json {
        print_run_json(&signed, &out_path)?;
    } else {
        print_run_summary(&signed, &out_path);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------

/// Compact machine-readable summary of a run/eval receipt (for `--json` and the MCP adapter).
fn print_run_json(sr: &bc::SignedReceipt, out: &Path) -> Result<()> {
    let b = &sr.body;
    let network = match b.policy.network {
        bc::NetworkPolicy::Deny => "deny",
        bc::NetworkPolicy::Allow => "allow",
    };
    let grade = b.grade.as_ref().map(|g| {
        serde_json::json!({
            "exit_code": g.outcome.exit_code,
            "isolated": g.isolated,
            "grader_digest": g.grader_digest,
        })
    });
    let egress = b.egress.as_ref().map(|e| {
        serde_json::json!({
            "calls": e.calls.len(),
            "denied": e.calls.iter().filter(|c| !c.allowed).count(),
            "allowlist": e.allowlist,
            "allowlist_digest": e.allowlist_digest,
            "log_head": e.log_head,
        })
    });
    let v = serde_json::json!({
        "seal_ok": b.seal_ok,
        "seal_notes": b.seal_notes,
        "exit_kind": b.outcome.exit_kind,
        "exit_code": b.outcome.exit_code,
        "wall_ms": b.outcome.wall_ms,
        "network": network,
        "net_ns": b.applied.net_ns,
        "deterministic": b.policy.deterministic,
        "inputs_root": b.inputs.root,
        "stdout_sha256": b.outcome.stdout_sha256,
        "stderr_sha256": b.outcome.stderr_sha256,
        "grade": grade,
        "egress": egress,
        "git_sealed": b.git_sealed,
        "receipt": out.display().to_string(),
        "pubkey": sr.pubkey,
        "body_digest": sr.body_digest,
    });
    println!("{}", serde_json::to_string(&v)?);
    Ok(())
}

fn print_run_summary(sr: &bc::SignedReceipt, out: &Path) {
    let b = &sr.body;
    let seal = if b.seal_ok {
        "SEAL HELD"
    } else {
        "SEAL BROKEN"
    };
    println!(
        "[bulla] {seal}  exit={} wall={}ms",
        exit_str(&b.outcome),
        b.outcome.wall_ms
    );
    println!(
        "  cell: net_ns={} user/pid/mount_ns={}/{}/{} pivot_root={} seccomp={} no_aslr={} fixed_env={}",
        b.applied.net_ns, b.applied.user_ns, b.applied.pid_ns, b.applied.mount_ns,
        b.applied.pivot_root, b.applied.seccomp, b.applied.no_aslr, b.applied.fixed_env
    );
    if let Some(gs) = b.git_sealed {
        println!(
            "  git:  {}",
            if gs {
                format!(
                    "sealed to a history-free HEAD={}",
                    short(b.git_head.as_deref().unwrap_or("?"))
                )
            } else {
                "PRESENT & UNSEALED — the fix may be mineable from .git".to_string()
            }
        );
    }
    println!(
        "  inputs: {} file(s), root={}",
        b.inputs.files.len(),
        short(&b.inputs.root)
    );
    println!(
        "  stdout sha256={} ({}B)   stderr sha256={} ({}B)",
        short(&b.outcome.stdout_sha256),
        b.outcome.stdout_bytes,
        short(&b.outcome.stderr_sha256),
        b.outcome.stderr_bytes
    );
    if let Some(g) = &b.grade {
        println!(
            "  grade: {}  exit={:?}  oracle_isolated={}  grader={}",
            if g.isolated {
                "isolated cell"
            } else {
                "SAME cell (tamperable)"
            },
            g.outcome.exit_code,
            g.isolated,
            short(&g.grader_digest)
        );
    }
    if let Some(e) = &b.egress {
        let denied = e.calls.iter().filter(|c| !c.allowed).count();
        println!(
            "  egress: mediated · {} call(s), {} denied · allowlist={} · log={}",
            e.calls.len(),
            denied,
            short(&e.allowlist_digest),
            short(&e.log_head)
        );
    }
    if !b.seal_ok {
        for n in &b.seal_notes {
            println!("  ! {n}");
        }
    }
    println!("  signed by {}  ->  {}", short(&sr.pubkey), out.display());
    println!("  verify:  bulla verify {}", out.display());
}

// ------------------------------------------------------------------------------------------------

fn cmd_verify(a: VerifyArgs) -> Result<()> {
    let bytes = fs::read(&a.receipt).with_context(|| format!("reading {}", a.receipt.display()))?;
    let sr: bc::SignedReceipt = serde_json::from_slice(&bytes).context("parsing receipt json")?;
    let r = bc::verify(&sr);
    let b = &sr.body;

    if a.json {
        let egress = b.egress.as_ref().map(|e| {
            serde_json::json!({"calls": e.calls.len(), "allowlist": e.allowlist, "log_head": e.log_head})
        });
        let v = serde_json::json!({
            "intact": r.intact(),
            "sig_ok": r.sig_ok,
            "digest_ok": r.digest_ok,
            "chain_ok": r.chain_ok,
            "seal_ok": r.seal_ok,
            "exit_kind": b.outcome.exit_kind,
            "exit_code": b.outcome.exit_code,
            "command": b.command,
            "notes": r.notes,
            "egress": egress,
        });
        println!("{}", serde_json::to_string(&v)?);
        if !r.intact() {
            std::process::exit(2);
        }
        return Ok(());
    }

    let mark = |ok: bool| if ok { "ok  " } else { "FAIL" };
    println!("bulla verify {}", a.receipt.display());
    println!("  schema      {}", b.schema);
    println!(
        "  signature   {}  (key {})",
        mark(r.sig_ok),
        short(&sr.pubkey)
    );
    println!(
        "  body digest {}  {}",
        mark(r.digest_ok),
        short(&sr.body_digest)
    );
    println!(
        "  event chain {}  head={}",
        mark(r.chain_ok),
        short(&b.chain_head)
    );
    println!("  ------------------------------------------------------------");
    println!(
        "  intact      {}   (unforged + internally consistent)",
        yn(r.intact())
    );
    println!(
        "  seal held   {}   (hermetic: no egress + private root + deterministic)",
        yn(r.seal_ok)
    );
    println!("  ------------------------------------------------------------");
    println!("  command     {}", b.command.join(" "));
    println!(
        "  policy      network={:?} deterministic={} git_hygiene={} wall_ms={}",
        b.policy.network, b.policy.deterministic, b.policy.git_hygiene, b.policy.wall_ms
    );
    println!(
        "  applied     net_ns={} user_ns={} pivot_root={} seccomp={} no_aslr={} fixed_env={}",
        b.applied.net_ns,
        b.applied.user_ns,
        b.applied.pivot_root,
        b.applied.seccomp,
        b.applied.no_aslr,
        b.applied.fixed_env
    );
    println!(
        "  git         {}",
        match b.git_sealed {
            None => "no repo in work dir".to_string(),
            Some(true) => format!(
                "sealed (history-free HEAD={})",
                short(b.git_head.as_deref().unwrap_or("?"))
            ),
            Some(false) => "present & UNSEALED (mineable)".to_string(),
        }
    );
    println!(
        "  outcome     exit={} wall={}ms   (solve phase)",
        exit_str(&b.outcome),
        b.outcome.wall_ms
    );
    if let Some(g) = &b.grade {
        println!(
            "  grade       exit={:?} in a {} (grader digest {})",
            g.outcome.exit_code,
            if g.isolated {
                "SEPARATE cell over the restored grader"
            } else {
                "SAME cell as the solve — TAMPERABLE"
            },
            short(&g.grader_digest)
        );
    }
    if let Some(e) = &b.egress {
        println!(
            "  egress      mediated · allowlist=[{}] (digest {}) · {} call(s) · log_head={}",
            e.allowlist.join(", "),
            short(&e.allowlist_digest),
            e.calls.len(),
            short(&e.log_head)
        );
        for c in &e.calls {
            println!(
                "                {} {}:{}{}  req={} resp={} ({}B)",
                if c.allowed { "ALLOW" } else { "DENY " },
                c.host,
                c.port,
                c.path,
                short(&c.req_sha256),
                short(&c.resp_sha256),
                c.resp_bytes
            );
        }
    }
    if !r.notes.is_empty() {
        println!("  notes:");
        for n in &r.notes {
            println!("    - {n}");
        }
    }
    if a.show {
        println!("{}", serde_json::to_string_pretty(&b)?);
    }

    // Exit non-zero if the receipt is not intact, so CI can gate on it.
    if !r.intact() {
        std::process::exit(2);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------

fn cmd_log(a: LogArgs) -> Result<()> {
    let entries = read_ledger(&a.ledger)?;
    let r = bc::verify_ledger(&entries);
    println!("bulla log {}", a.ledger.display());
    println!("  attempts    {}", r.attempts);
    println!(
        "  passed      {}  ({}%)",
        r.passes,
        pct(r.passes, r.attempts)
    );
    println!("  seal held   {}/{}", r.seal_held, r.attempts);
    println!(
        "  chain       {}",
        if r.chain_ok {
            "ok  (tamper-evident: no attempt dropped, reordered, or edited)".to_string()
        } else {
            format!(
                "BROKEN at seq {} — an attempt was dropped, reordered, or edited",
                r.break_at.unwrap_or(0)
            )
        }
    );
    if r.chain_ok && r.attempts > 1 && r.passes > 0 && r.passes < r.attempts {
        println!(
            "  ! nondeterministic: {}/{} attempts passed — a single lucky run is not pass@1",
            r.passes, r.attempts
        );
    }
    println!("  ------------------------------------------------------------");
    for e in &entries {
        let pass = e.grade_exit.or(e.solve_exit) == Some(0);
        println!(
            "    #{:<3} {}  seal={:<6} rcpt={}",
            e.seq,
            if pass { "PASS" } else { "FAIL" },
            if e.seal_ok { "HELD" } else { "BROKEN" },
            short(&e.receipt_digest)
        );
    }
    if !r.chain_ok {
        std::process::exit(2);
    }
    Ok(())
}

fn pct(n: u32, d: u32) -> u32 {
    n.saturating_mul(100).checked_div(d).unwrap_or(0)
}

fn read_ledger(path: &Path) -> Result<Vec<bc::LedgerEntry>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading ledger {}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            out.push(serde_json::from_str(line).context("parsing ledger entry")?);
        }
    }
    Ok(out)
}

fn ledger_head(path: &Path) -> Result<(String, u32)> {
    let zero = "0".repeat(64);
    if !path.exists() {
        return Ok((zero, 0));
    }
    let entries = read_ledger(path)?;
    Ok(match entries.last() {
        Some(e) => (e.hash.clone(), entries.len() as u32),
        None => (zero, 0),
    })
}

fn ledger_append(path: &Path, entry: &bc::LedgerEntry) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening ledger {}", path.display()))?;
    f.write_all(serde_json::to_string(entry)?.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// helpers

fn hash_work_dir(root: &Path) -> Result<bc::Manifest> {
    let mut entries = Vec::new();
    let skip = |name: &str| {
        matches!(
            name,
            ".bulla" | ".git" | "target" | "node_modules" | "__pycache__"
        )
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for ent in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let ent = ent?;
            let path = ent.path();
            let name = ent.file_name().to_string_lossy().to_string();
            let ft = ent.file_type()?;
            if ft.is_dir() {
                if !skip(&name) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                let data = fs::read(&path)?;
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push(bc::FileEntry {
                    path: rel,
                    sha256: bc::sha256_hex(&data),
                    bytes: data.len() as u64,
                });
            }
        }
    }
    Ok(bc::Manifest::from_entries(entries))
}

fn map_applied(a: &hc::Applied) -> bc::AppliedSummary {
    bc::AppliedSummary {
        user_ns: a.user_ns,
        pid_ns: a.pid_ns,
        mount_ns: a.mount_ns,
        net_ns: a.net_ns,
        uts_ns: a.uts_ns,
        ipc_ns: a.ipc_ns,
        cgroup_ns: a.cgroup_ns,
        pivot_root: a.pivot_root,
        no_new_privs: a.no_new_privs,
        no_aslr: a.no_aslr,
        fixed_env: a.fixed_env,
        seccomp: a.seccomp,
        loopback: a.loopback,
        cgroup: a.cgroup.clone(),
    }
}

fn map_outcome(o: &hc::Outcome) -> bc::OutcomeSummary {
    let (exit_kind, exit_code, signal) = match &o.exit {
        hc::ExitKind::Code { code } => ("code", Some(*code), None),
        hc::ExitKind::Signal { name, .. } => ("signal", None, Some(name.clone())),
        hc::ExitKind::Timeout { .. } => ("timeout", None, None),
        hc::ExitKind::SetupFailed { message } => ("setup_failed", None, Some(message.clone())),
    };
    bc::OutcomeSummary {
        exit_kind: exit_kind.into(),
        exit_code,
        signal,
        wall_ms: o.wall_ms,
        stdout_sha256: bc::sha256_hex(&o.stdout),
        stdout_bytes: o.stdout.len() as u64,
        stderr_sha256: bc::sha256_hex(&o.stderr),
        stderr_bytes: o.stderr.len() as u64,
    }
}

/// Host-only, per-work-dir state directory for trust material (key, ledger, egress log). NEVER inside
/// the cell-writable `/work` mount — so sandboxed code can neither read nor forge it.
fn state_dir(work: &Path) -> Result<PathBuf> {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let tag = bc::sha256_hex(work.to_string_lossy().as_bytes());
    let dir = base.join(".bulla").join(&tag[..16]);
    fs::create_dir_all(&dir).with_context(|| format!("creating state dir {}", dir.display()))?;
    Ok(dir)
}

/// Refuse a trust-material path that resolves inside the sandbox-writable work dir.
fn reject_inside_work(p: &Path, work: &Path, flag: &str) -> Result<()> {
    let target = p.parent().unwrap_or(p);
    let inside = match (target.canonicalize(), work.canonicalize()) {
        (Ok(a), Ok(b)) => a.starts_with(&b),
        _ => p.starts_with(work),
    };
    if inside {
        bail!(
            "{flag} must not resolve inside the work dir (writable by the sandboxed code): {}",
            p.display()
        );
    }
    Ok(())
}

/// Load a 32-byte Ed25519 seed from `path` (raw 32 bytes or 64 hex chars), creating one if absent.
fn load_or_create_seed(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let raw = fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
        if raw.len() == 32 {
            return Ok(<[u8; 32]>::try_from(raw).unwrap());
        }
        let txt = String::from_utf8_lossy(&raw);
        if let Some(seed) = bc::seed_from_hex(&txt) {
            return Ok(seed);
        }
        bail!(
            "key file {} is not 32 raw bytes or 64 hex chars",
            path.display()
        );
    }
    let seed = bc::generate_seed();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut f =
        fs::File::create(path).with_context(|| format!("creating key {}", path.display()))?;
    f.write_all(bc::seed_to_hex(&seed).as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(seed)
}

/// git-hygiene preflight. Returns `(git_sealed, head)`:
/// * `(None, None)` — no `.git` in the work dir;
/// * `(Some(false), head)` — a repo with history is present and was NOT sealed (fix mineable);
/// * `(Some(true), head)` — the repo was rebuilt as a single history-free commit.
fn seal_git(work: &Path, want_seal: bool) -> Result<(Option<bool>, Option<String>)> {
    if !work.join(".git").exists() {
        return Ok((None, None));
    }
    if !want_seal {
        return Ok((Some(false), git_head(work)));
    }
    // Rebuild a history-free single-commit repo from the current working tree: the tree is preserved,
    // but all history / refs / remotes / reflog are dropped — any future "fix" commit is gone.
    fs::remove_dir_all(work.join(".git")).ok();
    let git = |args: &[&str]| -> Result<()> {
        let st = Command::new("git")
            .args(args)
            .current_dir(work)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("running git {args:?}"))?;
        if !st.success() {
            bail!("git {args:?} failed (is git installed?)");
        }
        Ok(())
    };
    git(&["init", "-q"])?;
    git(&["add", "-A"])?;
    git(&[
        "-c",
        "user.email=seal@bulla",
        "-c",
        "user.name=bulla",
        "commit",
        "-q",
        "-m",
        "sealed checkout",
    ])?;
    git(&["gc", "--prune=now", "-q"])?;
    Ok((Some(true), git_head(work)))
}

fn git_head(work: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(work)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// One command run inside a fresh hermetic cell.
struct CellRun {
    outcome: hc::Outcome,
    applied: bc::AppliedSummary,
    summary: bc::OutcomeSummary,
    note: Option<String>,
}

fn run_in_cell(
    argv: &[String],
    work: &Path,
    network: &bc::NetworkPolicy,
    deterministic: bool,
    wall_ms: u64,
    allow_no_sandbox: bool,
) -> Result<CellRun> {
    let mut spec = hc::Spec::new(argv.to_vec(), work);
    spec.hermetic.no_network = matches!(network, bc::NetworkPolicy::Deny);
    if !deterministic {
        spec.hermetic.no_aslr = false;
        spec.hermetic.fixed_env = false;
    }
    spec.limits.wall = Duration::from_millis(wall_ms);
    let (outcome, note) = match hc::run(&spec) {
        Ok(o) => (o, None),
        // Fail-CLOSED (finding H1): if the sandbox can't be built, do NOT silently run the command
        // unconfined on the host. Only fall through to a direct run when explicitly opted in.
        Err(e) if !allow_no_sandbox => {
            bail!(
                "sandbox unavailable ({e}); refusing to run untrusted code unconfined. \
                 Re-run with --allow-no-sandbox to run WITHOUT isolation (the receipt will say SEAL BROKEN)."
            );
        }
        Err(e) => {
            eprintln!(
                "[bulla] --allow-no-sandbox: sandbox unavailable ({e}); running UNCONFINED on the host (SEAL BROKEN)"
            );
            (
                hc::run_direct(&spec)?,
                Some(format!("ran WITHOUT sandbox (--allow-no-sandbox): {e}")),
            )
        }
    };
    let applied = map_applied(&outcome.applied);
    let summary = map_outcome(&outcome);
    Ok(CellRun {
        outcome,
        applied,
        summary,
        note,
    })
}

/// Snapshot every file (bytes) under `root`, skipping bookkeeping dirs. Sorted by path.
fn snapshot_dir(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let skip = |n: &str| {
        matches!(
            n,
            ".bulla" | ".git" | "target" | "node_modules" | "__pycache__"
        )
    };
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for ent in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let ent = ent?;
            let path = ent.path();
            let name = ent.file_name().to_string_lossy().to_string();
            let ft = ent.file_type()?;
            if ft.is_dir() {
                if !skip(&name) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, fs::read(&path)?));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn manifest_from_snapshot(snap: &[(String, Vec<u8>)]) -> bc::Manifest {
    let files = snap
        .iter()
        .map(|(p, b)| bc::FileEntry {
            path: p.clone(),
            sha256: bc::sha256_hex(b),
            bytes: b.len() as u64,
        })
        .collect();
    bc::Manifest::from_entries(files)
}

/// sha256 over the selected trusted files (sorted) — the exact grader grading ran against.
fn digest_paths(snap: &[(String, Vec<u8>)], paths: &[String]) -> String {
    let mut sel: Vec<&(String, Vec<u8>)> = snap
        .iter()
        .filter(|(p, _)| paths.iter().any(|g| g == p))
        .collect();
    sel.sort_by(|a, b| a.0.cmp(&b.0));
    let mut buf = Vec::new();
    for (p, b) in sel {
        buf.extend_from_slice(p.as_bytes());
        buf.push(0);
        buf.extend_from_slice(b);
        buf.push(0);
    }
    bc::sha256_hex(&buf)
}

/// Build a fresh grade view: the trusted snapshot, then overlay only the agent's post-solve
/// content of the declared solution paths. Grader files stay trusted; agent-injected files
/// (a force-pass conftest.py, a trojanized binary) are absent — they never enter the grade cell.
fn build_grade_view(
    trusted: &[(String, Vec<u8>)],
    work: &Path,
    solution: &[String],
) -> Result<PathBuf> {
    // Unpredictable name + exclusive create (finding M3): `create_dir` fails if the path already
    // exists, so a local attacker cannot pre-plant a symlink to redirect the trusted-snapshot writes.
    let rnd = bc::seed_to_hex(&bc::generate_seed());
    let dir =
        std::env::temp_dir().join(format!("bulla-grade-{}-{}", std::process::id(), &rnd[..24]));
    fs::create_dir(&dir).with_context(|| format!("creating grade view {}", dir.display()))?;
    for (rel, bytes) in trusted {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, bytes)?;
    }
    for sp in solution {
        let src = work.join(sp);
        if src.is_file() {
            let dst = dir.join(sp);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src, &dst)?;
        }
    }
    Ok(dir)
}

// ---- TEE tier: detection + a clearly-labelled simulation of the attestation flow -----------------

/// Look for a hardware-enclave device on this host. Returns the (label, path) pairs actually present.
fn detect_tee() -> Vec<(&'static str, &'static str)> {
    [
        ("AMD SEV-SNP", "/dev/sev-guest"),
        ("Intel TDX", "/dev/tdx_guest"),
        ("Intel TDX", "/dev/tdx-guest"),
        ("Intel SGX", "/dev/sgx_enclave"),
        ("Intel SGX", "/dev/sgx/enclave"),
        ("AWS Nitro (NSM)", "/dev/nsm"),
    ]
    .into_iter()
    .filter(|(_, p)| Path::new(p).exists())
    .collect()
}

fn cmd_attest(a: AttestArgs) -> Result<()> {
    let found = detect_tee();
    let report_data = match &a.receipt {
        Some(rp) => {
            let bytes = fs::read(rp).with_context(|| format!("reading {}", rp.display()))?;
            let sr: bc::SignedReceipt =
                serde_json::from_slice(&bytes).context("parsing receipt json")?;
            Some(sr.body_digest)
        }
        None => None,
    };

    if !a.simulate {
        if a.json {
            let v = serde_json::json!({
                "tee_detected": found.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
                "real_attestation": false,
                "note": "detection only in this build; pass --simulate to demo the flow",
            });
            println!("{}", serde_json::to_string(&v)?);
            return Ok(());
        }
        println!("bulla attest — TEE tier (detection)");
        if found.is_empty() {
            println!(
                "  no TEE hardware detected (looked for SEV-SNP / TDX / SGX / Nitro devices)."
            );
        } else {
            for (l, p) in &found {
                println!("  detected: {l}  ({p})");
            }
        }
        println!("  Real hardware attestation is not implemented in this build. On a TEE host, bulla would");
        println!(
            "  generate the signing key INSIDE the enclave and emit a vendor-signed quote binding"
        );
        match &report_data {
            Some(d) => println!("  the receipt digest {} into report_data.", short(d)),
            None => println!("  a receipt digest into report_data (pass --receipt)."),
        }
        println!("  Try `bulla attest --simulate` to see the (clearly-labelled) flow.");
        return Ok(());
    }

    // SIMULATION — clearly labelled, never presented as a real hardware quote.
    let seed = bc::generate_seed(); // stands in for a key that would live only inside the enclave
    let enclave_pubkey = bc::pubkey_hex(&seed);
    let measurement = {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| fs::read(p).ok())
            .unwrap_or_default();
        bc::sha256_hex(&exe) // stands in for a launch measurement of the enclave image
    };
    let rd = report_data.clone().unwrap_or_else(|| "0".repeat(64));
    let signature = bc::sign_message(&seed, format!("{measurement}:{rd}").as_bytes());

    if a.json {
        let v = serde_json::json!({
            "simulated": true,
            "warning": "SIMULATED — NOT a hardware-backed attestation. For demonstration only.",
            "tee_type": "mock (real would be AMD SEV-SNP / Intel TDX / AWS Nitro)",
            "measurement": measurement,
            "report_data": rd,
            "enclave_pubkey": enclave_pubkey,
            "signature": signature,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("================================================================");
    println!("  SIMULATED ATTESTATION — NOT a hardware quote. Demo only.");
    println!("================================================================");
    println!("  tee_type        mock (real: AMD SEV-SNP / Intel TDX / AWS Nitro)");
    println!(
        "  measurement     {}  (mock image measurement)",
        short(&measurement)
    );
    println!(
        "  report_data     {}  (the receipt digest bound into the quote)",
        short(&rd)
    );
    println!(
        "  enclave_pubkey  {}  (would exist ONLY inside the enclave)",
        short(&enclave_pubkey)
    );
    println!(
        "  signature       {}  (mock enclave signature over measurement:report_data)",
        short(&signature)
    );
    println!();
    println!(
        "  On real hardware the quote is signed by the CPU vendor key chain, and a verifier checks"
    );
    println!(
        "  that chain plus the expected measurement. This build simulates the DATA + FLOW only."
    );
    Ok(())
}

// ---- smart egress: a mediated broker reachable only via a Unix socket in /work -------------------

/// Spawn the egress broker as a SEPARATE process (keeps this process single-threaded for the cell's
/// clone) and wait until it is listening. The socket lives in `/work` (the cell must reach it), but the
/// call **log lives in the host-only state dir** so the sandboxed code cannot forge it (finding C1).
fn start_egress_broker(work: &Path, state: &Path, allow: &[String]) -> Result<(Child, PathBuf)> {
    let sock = work.join(".bulla/egress.sock");
    let log = state.join("egress.log");
    if let Some(p) = sock.parent() {
        fs::create_dir_all(p).ok();
    }
    fs::remove_file(&sock).ok();
    fs::remove_file(&log).ok();
    let exe = std::env::current_exe().context("locating the bulla binary")?;
    let mut cmd = Command::new(exe);
    cmd.arg("egress-broker")
        .arg("--sock")
        .arg(&sock)
        .arg("--log")
        .arg(&log);
    for h in allow {
        cmd.arg("--allow").arg(h);
    }
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let child = cmd.spawn().context("spawning the egress broker")?;
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok((child, log))
}

/// Stop the broker and read its call log into a signed egress summary.
fn collect_egress(mut child: Child, log: &Path, allow: &[String]) -> bc::EgressSummary {
    let _ = child.kill();
    let _ = child.wait();
    let calls: Vec<bc::LoggedCall> = fs::read_to_string(log)
        .ok()
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default();
    bc::egress_summary(allow, &calls)
}

/// The broker (hidden subcommand). Listens on a Unix socket; for each connection it reads one request
/// line `HOST PORT PATH`, checks HOST against the allowlist, performs (or refuses) a plain HTTP/1.0 GET,
/// returns the bytes, and appends a hashed record of the call to the log. Runs until killed.
fn cmd_egress_broker(a: BrokerArgs) -> Result<()> {
    fs::remove_file(&a.sock).ok();
    if let Some(p) = a.sock.parent() {
        fs::create_dir_all(p).ok();
    }
    let listener = UnixListener::bind(&a.sock)
        .with_context(|| format!("binding egress socket {}", a.sock.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600, not world-writable (finding L1): the in-cell client shares the invoking uid.
        fs::set_permissions(&a.sock, fs::Permissions::from_mode(0o600)).ok();
    }
    let mut logf = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&a.log)?;

    const REQ_CAP: u64 = 8 * 1024; // bound the request line (finding M1)
    const RESP_CAP: u64 = 4 * 1024 * 1024; // bound the response held in host RAM (finding M1)

    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Read timeout so a client that never sends a newline can't stall the broker (M1).
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut line = String::new();
        {
            let clone = match stream.try_clone() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut r = BufReader::new(clone.take(REQ_CAP));
            if r.read_line(&mut line).is_err() {
                continue;
            }
        }
        let line = line.trim();
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            let _ = stream.write_all(b"ERROR bad request (want: HOST PORT PATH)\n");
            continue;
        }
        let host = parts[0].to_string();
        let port: u16 = parts[1].parse().unwrap_or(0);
        let path = parts[2].to_string();
        // Allowlist matches (host, port) — a bare host permits only 80/443 (finding H2).
        let allowed = allowlist_ok(&a.allow, &host, port);
        let req_sha256 = bc::sha256_hex(format!("{host} {port} {path}").as_bytes());

        let (resolved_ip, resp_sha256, resp_bytes) = if !allowed {
            let _ = stream.write_all(b"DENIED not on allowlist\n");
            (String::new(), bc::sha256_hex(b""), 0u64)
        } else {
            match resolve_and_validate(&host, port) {
                Err(e) => {
                    let _ = stream.write_all(format!("DENIED {e}\n").as_bytes());
                    (String::new(), bc::sha256_hex(b""), 0u64)
                }
                Ok(addr) => match http_get(addr, &host, &path, RESP_CAP) {
                    Ok(bytes) => {
                        let _ = stream.write_all(&bytes);
                        (
                            addr.ip().to_string(),
                            bc::sha256_hex(&bytes),
                            bytes.len() as u64,
                        )
                    }
                    Err(e) => {
                        let _ = stream.write_all(format!("ERROR {e}\n").as_bytes());
                        (addr.ip().to_string(), bc::sha256_hex(b""), 0u64)
                    }
                },
            }
        };
        let call = bc::LoggedCall {
            host,
            port,
            path,
            allowed,
            resolved_ip,
            req_sha256,
            resp_sha256,
            resp_bytes,
        };
        if let Ok(js) = serde_json::to_string(&call) {
            let _ = writeln!(logf, "{js}");
            let _ = logf.flush();
        }
    }
    Ok(())
}

/// True if `(host, port)` is permitted. An allowlist entry `host:port` pins that exact port; a bare
/// `host` permits only 80/443. Port is attacker-controlled, so it must be checked (finding H2).
fn allowlist_ok(allow: &[String], host: &str, port: u16) -> bool {
    allow.iter().any(|entry| match entry.split_once(':') {
        Some((h, p)) => h == host && p.parse::<u16>() == Ok(port),
        None => entry == host && (port == 80 || port == 443),
    })
}

fn is_internal(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    fn v4_internal(v: &std::net::Ipv4Addr) -> bool {
        let o = v.octets();
        v.is_loopback()
            || v.is_private()
            || v.is_link_local()
            || v.is_unspecified()
            || v.is_broadcast()
            || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // CGNAT 100.64.0.0/10
    }
    match ip {
        IpAddr::V4(v) => v4_internal(v),
        IpAddr::V6(v) => {
            // Classify IPv4-mapped addresses (e.g. ::ffff:169.254.169.254) on their v4 form (N2).
            if let Some(v4) = v.to_ipv4_mapped() {
                return v4_internal(&v4);
            }
            v.is_loopback()
                || v.is_unspecified()
                || (v.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Resolve `host:port` ONCE (pinning the IP to defeat DNS rebinding) and reject internal targets
/// unless the client asked for that literal IP (finding H2).
fn resolve_and_validate(
    host: &str,
    port: u16,
) -> std::result::Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;
    if is_internal(&addr.ip()) && host.parse::<std::net::IpAddr>().ok() != Some(addr.ip()) {
        return Err(format!(
            "blocked internal target {} (possible DNS rebinding)",
            addr.ip()
        ));
    }
    Ok(addr)
}

/// A dependency-free HTTP/1.0 GET to an ALREADY-RESOLVED, pinned address, with a bounded response.
fn http_get(
    addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    max_bytes: u64,
) -> std::result::Result<Vec<u8>, String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream
        .take(max_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn short(h: &str) -> String {
    let head: String = h.chars().take(12).collect();
    if head.len() < h.len() {
        format!("{head}…")
    } else {
        head
    }
}
fn yn(b: bool) -> &'static str {
    if b {
        "YES"
    } else {
        "NO "
    }
}
fn exit_str(o: &bc::OutcomeSummary) -> String {
    match o.exit_kind.as_str() {
        "code" => format!("code:{}", o.exit_code.unwrap_or(-1)),
        "signal" => format!("signal:{}", o.signal.clone().unwrap_or_default()),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{allowlist_ok, is_internal};
    use std::net::IpAddr;

    #[test]
    fn allowlist_enforces_port() {
        let allow = vec!["api.example.com".to_string(), "127.0.0.1:8799".to_string()];
        assert!(allowlist_ok(&allow, "api.example.com", 443)); // bare host -> 443 ok
        assert!(allowlist_ok(&allow, "api.example.com", 80)); // bare host -> 80 ok
        assert!(!allowlist_ok(&allow, "api.example.com", 8080)); // bare host -> other port denied
        assert!(allowlist_ok(&allow, "127.0.0.1", 8799)); // pinned port ok
        assert!(!allowlist_ok(&allow, "127.0.0.1", 22)); // off-port denied (H2)
        assert!(!allowlist_ok(&allow, "evil.example", 443)); // off-host denied
    }

    #[test]
    fn is_internal_blocks_internal_and_mapped_and_cgnat() {
        let internal = [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "::1",
            "::ffff:169.254.169.254", // IPv4-mapped metadata (N2)
            "::ffff:127.0.0.1",       // IPv4-mapped loopback (N2)
            "fe80::1",                // link-local
            "fc00::1",                // unique-local
        ];
        for s in internal {
            assert!(
                is_internal(&s.parse::<IpAddr>().unwrap()),
                "{s} must be internal"
            );
        }
        let external = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ];
        for s in external {
            assert!(
                !is_internal(&s.parse::<IpAddr>().unwrap()),
                "{s} must be external"
            );
        }
    }
}
