//! Demo: an autonomous trading agent proves — in zero knowledge — that its order is within a risk
//! cap, and a broker verifies it WITHOUT ever learning the order size or the strategy.
//!
//!   cargo run -p bulla-zk --example risk_proof

use bulla_zk::{prove_within_cap, verify_within_cap};

fn main() {
    let cap_bits = 16usize;
    let cap = 1u64 << cap_bits;
    let secret_order = 4200u64; // the agent's private position size — never published

    println!("agent:  secret order size = {secret_order}  (never revealed)");
    println!("policy: risk cap = 2^{cap_bits} = {cap}");

    let proof = prove_within_cap(secret_order, cap_bits);
    println!("\npublished (all a broker / investor ever sees):");
    println!("  commitment = {}…", &proof.commitment[..24]);
    println!("  proof      = {} bytes", proof.proof.len() / 2);
    println!("  cap_bits   = {}", proof.cap_bits);

    let ok = verify_within_cap(&proof);
    println!("\nbroker verifies WITHOUT seeing the order:  within risk cap = {ok}");

    let over = prove_within_cap(cap + 500, cap_bits);
    let over_ok = verify_within_cap(&over);
    println!("negative check · over-cap order verifies = {over_ok}  (must be false)");

    let mut tampered = proof.clone();
    let mut b = tampered.proof.into_bytes();
    b[10] ^= 0x01;
    tampered.proof = String::from_utf8(b).unwrap();
    let tampered_ok = verify_within_cap(&tampered);
    println!("negative check · tampered proof verifies = {tampered_ok}  (must be false)");

    let result = serde_json::json!({
        "within_cap": ok,
        "over_cap_verifies": over_ok,
        "tampered_verifies": tampered_ok,
        "cap_bits": cap_bits,
        "proof_bytes": proof.proof.len() / 2,
    });
    println!("\nRESULT {result}");
}
