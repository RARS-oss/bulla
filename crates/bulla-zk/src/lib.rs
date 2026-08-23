//! bulla-zk — a **real** zero-knowledge proof that a secret quantity is within a committed risk limit.
//!
//! An autonomous trading agent must convince a broker/investor that every order respects a risk
//! cap — *without revealing the position size or the strategy behind it*. That is exactly what a
//! zero-knowledge **range proof** provides: the prover publishes a Pedersen commitment to the order
//! size and a [Bulletproof](https://crypto.stanford.edu/bulletproofs/) that the committed value lies
//! in `[0, 2^cap_bits)`. The verifier learns **only** that the order is within the cap — never the
//! value, never the strategy.
//!
//! This complements the sandbox: a `bulla` receipt proves *the code ran in a sealed cell*; a
//! `bulla-zk` proof proves *the order it produced respects the risk limit* — privately. Together:
//! "sealed execution + provably-bounded, secret strategy."
//!
//! This is genuine ZK (Bulletproofs over Ristretto25519), not a commitment or a hash — the value is
//! information-theoretically hidden by the Pedersen blinding, and soundness rests on the proof.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Transcript domain separator — prover and verifier must agree on it.
const DOMAIN: &[u8] = b"bulla-zk/risk-limit/v0";

/// A publishable, self-verifying risk-limit proof. Reveals nothing about the order beyond
/// "0 <= order < 2^cap_bits".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskProof {
    /// The risk cap is `2^cap_bits` (must be one of 8, 16, 32, 64 — Bulletproofs needs a power of two).
    pub cap_bits: usize,
    /// Hex Pedersen commitment to the (secret) order size.
    pub commitment: String,
    /// Hex Bulletproof.
    pub proof: String,
}

fn gens(cap_bits: usize) -> (PedersenGens, BulletproofGens) {
    // 64 supports every valid cap_bits (8/16/32/64); party capacity 1 (single value).
    let _ = cap_bits;
    (PedersenGens::default(), BulletproofGens::new(64, 1))
}

/// Prove, in zero knowledge, that `order` is within the `2^cap_bits` risk cap. The order value never
/// leaves this function; only the commitment + proof do.
pub fn prove_within_cap(order: u64, cap_bits: usize) -> RiskProof {
    let (pc, bp) = gens(cap_bits);
    let blinding = Scalar::random(&mut rand::rngs::OsRng);
    let mut t = Transcript::new(DOMAIN);
    let (proof, commit) = RangeProof::prove_single(&bp, &pc, &mut t, order, &blinding, cap_bits)
        .expect("bulletproofs range proof");
    RiskProof {
        cap_bits,
        commitment: hex::encode(commit.as_bytes()),
        proof: hex::encode(proof.to_bytes()),
    }
}

/// Verify a risk-limit proof: returns true iff the committed value is provably in `[0, 2^cap_bits)`.
/// The verifier never sees the order size.
pub fn verify_within_cap(p: &RiskProof) -> bool {
    let (pc, bp) = gens(p.cap_bits);
    let commit = match hex::decode(&p.commitment)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(arr) => CompressedRistretto(arr),
        None => return false,
    };
    let proof_bytes = match hex::decode(&p.proof) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut vt = Transcript::new(DOMAIN);
    proof
        .verify_single(&bp, &pc, &mut vt, &commit, p.cap_bits)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_cap_order_proves_and_verifies_hiding_the_value() {
        let p = prove_within_cap(4200, 16); // order 4200, cap 2^16 = 65536
        assert!(verify_within_cap(&p), "an in-cap order must verify");
        // the proof reveals only the cap and opaque bytes — the value 4200 appears nowhere.
        assert!(!p.commitment.contains("4200") && !p.proof.contains("4200"));
    }

    #[test]
    fn a_tampered_proof_does_not_verify() {
        let mut p = prove_within_cap(4200, 16);
        // flip one hex nibble of the proof
        let mut bytes = p.proof.into_bytes();
        bytes[10] ^= 0x01;
        p.proof = String::from_utf8(bytes).unwrap();
        assert!(!verify_within_cap(&p), "a mutated proof must fail");
    }

    #[test]
    fn a_proof_does_not_verify_against_another_commitment() {
        let p1 = prove_within_cap(1000, 16);
        let p2 = prove_within_cap(2000, 16);
        // swap in a different commitment: the proof no longer matches
        let forged = RiskProof {
            commitment: p2.commitment,
            ..p1
        };
        assert!(
            !verify_within_cap(&forged),
            "proof must bind to its commitment"
        );
    }

    #[test]
    fn an_out_of_cap_order_fails_verification() {
        // 70000 > 2^16 - 1: a "proof" can be produced, but it cannot verify — this is the soundness
        // that makes the risk-limit claim meaningful.
        let p = prove_within_cap(70000, 16);
        assert!(
            !verify_within_cap(&p),
            "an out-of-cap order must not verify"
        );
    }
}
