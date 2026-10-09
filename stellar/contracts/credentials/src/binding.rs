//! Proof/statement binding.
//!
//! UltraHonk's `UltraKeccakFlavor` verifier (the only flavour implemented by the
//! audited upstream crate) does **not** bind a proof to the transaction
//! submitter and provides **no replay protection**. Both properties are supplied
//! here instead, by forcing every proof to carry exactly one public input: a
//! digest over a canonical statement that names this contract, this subject, this
//! issuer, this program, this commitment, this nullifier and this expiry.
//!
//! A proof therefore only verifies against the single statement it was generated
//! for, and re-using it anywhere else fails the equality check in
//! [`crate::MediTrustCredentials::issue_credential`].

use soroban_sdk::{contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

/// Domain separation tag for credential statements.
pub const DOMAIN_TAG: &[u8] = b"meditrust:health-credential:v1";

/// The statement a credential proof must be bound to.
///
/// This mirrors the circuit's declaration exactly: the circuit exposes one public
/// input, and every field below is part of the digest that produces it. See
/// `docs/zk-pipeline.md` for the circuit-side definition.
#[contracttype]
#[derive(Clone)]
pub struct CredentialStatement {
    /// `sha256(DOMAIN_TAG)`.
    pub domain: BytesN<32>,
    /// The credential contract itself, so a proof cannot be replayed against a
    /// second deployment.
    pub contract: Address,
    /// Wallet the credential is bound to (non-transferable).
    pub subject: Address,
    /// Training provider that attested the training.
    pub issuer: Address,
    /// Registered training program.
    pub program_id: BytesN<32>,
    /// Commitment to the holder's off-chain training record.
    pub subject_commitment: BytesN<32>,
    /// Single-use attestation nullifier.
    pub nullifier: BytesN<32>,
    /// Credential expiry, unix seconds.
    pub expires_at: u64,
}

impl CredentialStatement {
    /// `sha256` over the canonical XDR encoding of the statement.
    ///
    /// XDR of the `ScVal` form is used because it is deterministic, canonical and
    /// available to both the on-chain contract and off-chain provers via the same
    /// `soroban-sdk` types.
    pub fn digest(&self, env: &Env) -> BytesN<32> {
        // `Crypto::sha256` yields a `Hash<32>`, which converts into `BytesN<32>`.
        env.crypto().sha256(&self.clone().to_xdr(env)).into()
    }
}

/// `sha256(DOMAIN_TAG)`, recomputed rather than hard-coded so the tag stays
/// greppable in source.
pub fn domain(env: &Env) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, DOMAIN_TAG))
        .into()
}

/// Derives the single canonical public input for a statement.
///
/// UltraHonk public inputs are 32-byte big-endian BN254 scalars. A raw `sha256`
/// digest is not guaranteed to be a canonical field element, so the digest is
/// truncated to 31 bytes and left-padded with a zero: the resulting integer is
/// below `2^248`, comfortably under the BN254 scalar modulus (~`2^254`).
pub fn public_inputs(env: &Env, statement: &CredentialStatement) -> Bytes {
    let digest = statement.digest(env).to_array();
    let mut field = [0u8; 32];
    field[1..].copy_from_slice(&digest[..31]);
    Bytes::from_array(env, &field)
}
