//! End-to-end integration tests: they invoke the real `bulla` binary and assert on its receipts.
//! Robust across environments — they check *intactness* (always true for a fresh receipt), not
//! `seal_ok`, since a host without unprivileged user namespaces falls back to an un-isolated run.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bulla"))
}

fn tmpdir() -> PathBuf {
    static C: AtomicU64 = AtomicU64::new(0);
    let n = C.fetch_add(1, Ordering::Relaxed);
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("bulla-it-{}-{}-{}", std::process::id(), ns, n));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn run_produces_a_verifiable_receipt() {
    let work = tmpdir();
    let receipt = work.join("r.json");

    let out = bin()
        .args(["run", "--work"])
        .arg(&work)
        .args(["--json", "--out"])
        .arg(&receipt)
        .args(["--", "sh", "-c", "echo hello; exit 0"])
        .output()
        .expect("run bulla");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: Value = serde_json::from_slice(&out.stdout).expect("run --json is valid JSON");
    assert_eq!(v["exit_code"], 0);
    assert!(v["seal_ok"].is_boolean());
    assert!(receipt.is_file(), "the receipt file must be written");

    // verify --json: the fresh receipt is intact and its signature checks out.
    let vout = bin()
        .args(["verify", "--json"])
        .arg(&receipt)
        .output()
        .expect("verify bulla");
    assert!(
        vout.status.success(),
        "verify should exit 0 on an intact receipt"
    );
    let vr: Value = serde_json::from_slice(&vout.stdout).expect("verify --json is valid JSON");
    assert_eq!(vr["intact"], true);
    assert_eq!(vr["sig_ok"], true);
    assert_eq!(vr["chain_ok"], true);

    fs::remove_dir_all(&work).ok();
}

#[test]
fn a_tampered_receipt_fails_verification() {
    let work = tmpdir();
    let receipt = work.join("r.json");
    bin()
        .args(["run", "--work"])
        .arg(&work)
        .args(["--out"])
        .arg(&receipt)
        .args(["--", "sh", "-c", "exit 7"])
        .output()
        .expect("run bulla");

    // forge the reported exit code inside the signed body.
    let mut doc: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    doc["body"]["outcome"]["exit_code"] = Value::from(0);
    fs::write(&receipt, serde_json::to_vec(&doc).unwrap()).unwrap();

    let vout = bin()
        .args(["verify"])
        .arg(&receipt)
        .output()
        .expect("verify");
    assert!(
        !vout.status.success(),
        "verify must exit non-zero on a tampered receipt"
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn keygen_prints_a_public_key() {
    let dir = tmpdir();
    let key = dir.join("k.seed");
    let out = bin()
        .args(["keygen", "--key"])
        .arg(&key)
        .output()
        .expect("keygen");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("pubkey "), "keygen should print a pubkey: {s}");
    assert!(key.is_file(), "the seed file should be created");

    fs::remove_dir_all(&dir).ok();
}
