//! End-to-end UltraHonk verification against real circuit artifacts.
//!
//! Proof artifacts are large and must be regenerated for every circuit revision,
//! so they are not committed. Point `MEDTRUST_ULTRAHONK_ARTIFACTS` at a directory
//! containing:
//!
//! * `vk` — output of `bb write_vk`
//! * `proof` — output of `bb prove`
//! * `public_inputs` — the matching public inputs
//!
//! produced with `nargo` + `bb` using the Keccak transcript (`--oracle_hash keccak`).
//! See `docs/zk-pipeline.md`. When the variable is unset these tests report a skip
//! rather than passing silently.
//!
//! ```text
//! MEDTRUST_ULTRAHONK_ARTIFACTS=circuits/credential_attestation/target \
//!   cargo test -p meditrust-verifier --test ultrahonk_artifacts -- --nocapture
//! ```

use std::fs;
use std::path::PathBuf;

use meditrust_verifier::{MediTrustVerifier, MediTrustVerifierClient};
use soroban_sdk::{Bytes, Env, String};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

/// Exact serialized size of an UltraHonk verification key.
const VK_BYTES: usize = 1760;

fn artifacts_dir() -> Option<PathBuf> {
    std::env::var("MEDTRUST_ULTRAHONK_ARTIFACTS")
        .ok()
        .map(PathBuf::from)
}

/// Loads the three artifacts, or skips the test with a visible message.
macro_rules! artifacts_or_skip {
    () => {
        match artifacts_dir() {
            Some(dir) => {
                let read = |name: &str| {
                    let path = dir.join(name);
                    fs::read(&path)
                        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
                };
                (read("vk"), read("proof"), read("public_inputs"))
            }
            None => {
                println!(
                    "SKIP: set MEDTRUST_ULTRAHONK_ARTIFACTS to a directory containing \
                     vk, proof and public_inputs to run UltraHonk end-to-end tests"
                );
                return;
            }
        }
    };
}

fn deploy<'a>(env: &'a Env, vk: &Bytes) -> MediTrustVerifierClient<'a> {
    let contract_id = env.register(
        MediTrustVerifier,
        (String::from_str(env, "meditrust-credential-v1"), vk.clone()),
    );
    MediTrustVerifierClient::new(env, &contract_id)
}

#[test]
#[ignore = "requires UltraHonk circuit artifacts; run with --include-ignored and MEDTRUST_ULTRAHONK_ARTIFACTS set"]
fn verifies_a_genuine_ultrahonk_proof() {
    let (vk_raw, proof_raw, public_inputs_raw) = artifacts_or_skip!();
    let env = Env::default();
    let vk = Bytes::from_slice(&env, &vk_raw);
    let proof = Bytes::from_slice(&env, &proof_raw);
    let public_inputs = Bytes::from_slice(&env, &public_inputs_raw);

    let client = deploy(&env, &vk);

    assert!(
        client.verify_proof(&public_inputs, &proof),
        "a genuine proof must verify against its own verification key"
    );

    let expected: soroban_sdk::BytesN<32> = env.crypto().sha256(&vk).into();
    assert_eq!(
        client.verification_key_hash(),
        expected,
        "the deployed verifier must pin the exact key it was built with"
    );
    assert_eq!(
        client.circuit_id(),
        String::from_str(&env, "meditrust-credential-v1")
    );
}

#[test]
#[ignore = "requires UltraHonk circuit artifacts; run with --include-ignored and MEDTRUST_ULTRAHONK_ARTIFACTS set"]
fn rejects_a_truncated_proof() {
    let (vk_raw, proof_raw, public_inputs_raw) = artifacts_or_skip!();
    let env = Env::default();
    let vk = Bytes::from_slice(&env, &vk_raw);
    let proof = Bytes::from_slice(&env, &proof_raw);
    let public_inputs = Bytes::from_slice(&env, &public_inputs_raw);

    let client = deploy(&env, &vk);
    let truncated = proof.slice(..(proof.len() / 2));

    // A malformed proof must produce a clean `false`, never a trap.
    assert!(!client.verify_proof(&public_inputs, &truncated));
}

#[test]
#[ignore = "requires UltraHonk circuit artifacts; run with --include-ignored and MEDTRUST_ULTRAHONK_ARTIFACTS set"]
fn rejects_a_proof_against_tampered_public_inputs() {
    let (vk_raw, proof_raw, public_inputs_raw) = artifacts_or_skip!();
    let env = Env::default();
    let vk = Bytes::from_slice(&env, &vk_raw);
    let proof = Bytes::from_slice(&env, &proof_raw);
    let public_inputs = Bytes::from_slice(&env, &public_inputs_raw);

    let client = deploy(&env, &vk);

    // Baseline: the untouched inputs verify, so the tampered case below is a
    // meaningful negative rather than a blanket failure.
    assert!(client.verify_proof(&public_inputs, &proof));

    let mut tampered = public_inputs_raw.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered = Bytes::from_slice(&env, &tampered);

    assert!(
        !client.verify_proof(&tampered, &proof),
        "a proof must not verify against public inputs it was not generated for"
    );
}

#[test]
#[ignore = "requires UltraHonk circuit artifacts; run with --include-ignored and MEDTRUST_ULTRAHONK_ARTIFACTS set"]
fn rejects_a_corrupted_verification_key() {
    let (vk_raw, _proof_raw, _public_inputs_raw) = artifacts_or_skip!();
    let env = Env::default();

    assert_eq!(vk_raw.len(), VK_BYTES);

    let mut corrupted = vk_raw.clone();
    corrupted[0] ^= 0xff;
    let corrupted = Bytes::from_slice(&env, &corrupted);

    // The guard the constructor relies on: a key the library cannot load must
    // never reach a deployed verifier, because a deployed verifier is immutable.
    assert!(
        UltraHonkVerifier::new(&env, &corrupted).is_err(),
        "a corrupted verification key must not be loadable"
    );
    // ...and the unmodified key still loads, so the check above is meaningful.
    assert!(UltraHonkVerifier::new(&env, &Bytes::from_slice(&env, &vk_raw)).is_ok());
}
