//! Cross-contract interface to a proof-system verifier.
//!
//! The credential contract never embeds a proof system. It talks to whichever
//! verifier the admin has configured through this minimal interface, which
//! `meditrust-verifier` implements on top of the audited UltraHonk crate. Keeping
//! the boundary this narrow means the credential logic is identical no matter
//! which circuit or proving system sits behind it.

use soroban_sdk::{contractclient, Bytes, BytesN, Env};

/// Minimal interface required from a proof verifier.
///
/// The trait itself is only used by the `contractclient` macro to generate
/// [`ProofVerifierClient`]; nothing calls its methods directly.
#[allow(dead_code)]
#[contractclient(name = "ProofVerifierClient")]
pub trait ProofVerifier {
    /// Returns `true` only if `proof` verifies for exactly `public_inputs`.
    ///
    /// Implementations must never fail open and should not panic on malformed
    /// input; the credential contract treats both `false` and a trapped call as
    /// rejection.
    fn verify_proof(env: Env, public_inputs: Bytes, proof: Bytes) -> bool;

    /// `sha256` of the verification key the verifier is pinned to.
    fn verification_key_hash(env: Env) -> BytesN<32>;
}
