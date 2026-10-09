//! Tests for the verifier contract's deployment guards.
//!
//! The happy path — verifying a genuine proof — requires artifacts produced by
//! `nargo` + `bb`, which are not committed. It is covered by
//! `tests/ultrahonk_artifacts.rs`, which runs when artifacts are supplied via
//! `MEDTRUST_ULTRAHONK_ARTIFACTS`. What is tested here are the guards that must
//! hold regardless: a verifier may never be deployed with a key it cannot use.

use soroban_sdk::{Bytes, Env, String};

use super::*;

/// Exact serialized size of an UltraHonk verification key.
const VK_BYTES: usize = 1760;

#[test]
fn library_rejects_a_key_of_the_wrong_length() {
    let env = Env::default();
    let vk = Bytes::from_slice(&env, &[0u8; VK_BYTES - 1]);
    assert!(
        UltraHonkVerifier::new(&env, &vk).is_err(),
        "a truncated verification key must not be loadable"
    );
}

#[test]
fn library_rejects_a_zero_filled_key() {
    let env = Env::default();
    // Correct byte count, but the header and group elements are meaningless.
    let vk = Bytes::from_slice(&env, &[0u8; VK_BYTES]);
    assert!(
        UltraHonkVerifier::new(&env, &vk).is_err(),
        "structural validation must reject a zero-filled key"
    );
}

#[test]
fn library_rejects_a_bogus_prefix() {
    let env = Env::default();
    let mut raw = [0u8; VK_BYTES];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let vk = Bytes::from_slice(&env, &raw);
    assert!(
        UltraHonkVerifier::new(&env, &vk).is_err(),
        "a key whose group elements are not on the curve must be rejected"
    );
}

/// Deployment must fail fast rather than leave a verifier that can never verify.
#[test]
#[should_panic]
fn constructor_rejects_an_empty_key() {
    let env = Env::default();
    let _ = env.register(
        MediTrustVerifier,
        (
            String::from_str(&env, "meditrust-credential-v1"),
            Bytes::new(&env),
        ),
    );
}

#[test]
#[should_panic]
fn constructor_rejects_a_malformed_key() {
    let env = Env::default();
    let _ = env.register(
        MediTrustVerifier,
        (
            String::from_str(&env, "meditrust-credential-v1"),
            Bytes::from_slice(&env, &[0u8; VK_BYTES]),
        ),
    );
}
