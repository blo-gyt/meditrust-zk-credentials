#![no_std]
//! # MediTrust UltraHonk verifier
//!
//! A thin, stateless-per-call Soroban contract that verifies Noir / UltraHonk
//! proofs produced by `nargo` + `bb` (Barretenberg). The verification key is
//! fixed at deploy time and can never be rotated, so the credential contract
//! always knows exactly which circuit it is trusting.
//!
//! ## Scope and caveats
//!
//! The underlying `ultrahonk_soroban_verifier` crate implements the
//! **UltraKeccakFlavor only**, which is *not* zero-knowledge:
//!
//! * it provides no witness-hiding guarantee, and
//! * it does not bind a proof to the transaction submitter, and
//! * it provides no replay protection.
//!
//! The verifier contract therefore exposes only a boolean verification
//! primitive. All replay protection, subject binding and domain separation are
//! the responsibility of the caller (`meditrust-credentials`), which binds each
//! proof to an exact set of canonical public inputs. See
//! `docs/security-model.md`.

use soroban_sdk::{contract, contractimpl, contracttype, Bytes, BytesN, Env, String};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

mod error;
#[cfg(test)]
mod test;

pub use error::VerifierError;

/// Storage keys. All verifier state lives in *instance* storage: it is set once
/// by the constructor and read on every proof check.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Raw UltraHonk verification key bytes, exactly as emitted by `bb write_vk`.
    VerificationKey,
    /// `sha256(VerificationKey)`, used by clients to pin an exact circuit build.
    VerificationKeyHash,
    /// Human-readable circuit identifier, e.g. `meditrust-credential-v1`.
    CircuitId,
}

/// Instance-entry TTL management. Instance storage is bumped on every call that
/// touches it so a live verifier never archives.
const INSTANCE_TTL_THRESHOLD: u32 = 17_280 * 7; // ~7 days at 5s ledgers
const INSTANCE_TTL_EXTEND_TO: u32 = 17_280 * 30; // ~30 days

#[contract]
pub struct MediTrustVerifier;

#[contractimpl]
impl MediTrustVerifier {
    /// Deploys a verifier permanently pinned to a single verification key.
    ///
    /// The key is parsed eagerly so that a malformed circuit build fails at
    /// deployment rather than on the first credential issuance.
    pub fn __constructor(
        env: Env,
        circuit_id: String,
        verification_key: Bytes,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&DataKey::VerificationKey) {
            return Err(VerifierError::AlreadyInitialized);
        }
        if verification_key.is_empty() {
            return Err(VerifierError::EmptyVerificationKey);
        }
        // Fail closed at deploy time: refuse a key we cannot even parse.
        UltraHonkVerifier::new(&env, &verification_key)
            .map_err(|_| VerifierError::InvalidVerificationKey)?;

        let digest: BytesN<32> = env.crypto().sha256(&verification_key).into();

        env.storage()
            .instance()
            .set(&DataKey::VerificationKey, &verification_key);
        env.storage()
            .instance()
            .set(&DataKey::VerificationKeyHash, &digest);
        env.storage()
            .instance()
            .set(&DataKey::CircuitId, &circuit_id);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        Ok(())
    }

    /// Returns `true` only if `proof` verifies against the pinned verification
    /// key for exactly `public_inputs`.
    ///
    /// Never panics and never fails open: a missing key, an unparsable key, a
    /// malformed proof or a failed check all return `false`.
    pub fn verify_proof(env: Env, public_inputs: Bytes, proof: Bytes) -> bool {
        let verification_key: Bytes = match env.storage().instance().get(&DataKey::VerificationKey)
        {
            Some(key) => key,
            None => return false,
        };

        let verifier = match UltraHonkVerifier::new(&env, &verification_key) {
            Ok(verifier) => verifier,
            Err(_) => return false,
        };

        verifier.verify(&proof, &public_inputs).is_ok()
    }

    /// `sha256` of the pinned verification key. Lets the credential contract
    /// record which circuit attested a given credential.
    pub fn verification_key_hash(env: Env) -> Result<BytesN<32>, VerifierError> {
        env.storage()
            .instance()
            .get(&DataKey::VerificationKeyHash)
            .ok_or(VerifierError::NotInitialized)
    }

    /// Human-readable identifier of the pinned circuit.
    pub fn circuit_id(env: Env) -> Result<String, VerifierError> {
        env.storage()
            .instance()
            .get(&DataKey::CircuitId)
            .ok_or(VerifierError::NotInitialized)
    }
}
