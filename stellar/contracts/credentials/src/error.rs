use soroban_sdk::contracterror;

/// Every failure mode of the credential protocol.
///
/// Errors are stable codes: clients and indexers may rely on the numeric value.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// The constructor has already run.
    AlreadyInitialized = 1,
    /// The contract has not been configured.
    NotInitialized = 2,
    /// The caller is not the protocol admin.
    NotAdmin = 3,
    /// The issuer is not on the allowlist, or has been removed from it.
    IssuerNotAuthorized = 4,
    /// No training program is registered under this `program_id`.
    ProgramNotRegistered = 5,
    /// The training program exists but is suspended.
    ProgramSuspended = 6,
    /// The attestation nullifier has already been consumed.
    NullifierAlreadyUsed = 7,
    /// `expires_at` is not in the future.
    InvalidExpiry = 8,
    /// The supplied public inputs are not the canonical encoding for this
    /// issuance statement, so the proof is bound to a different statement.
    PublicInputMismatch = 9,
    /// The proof did not verify (or the verifier could not be reached).
    ProofVerificationFailed = 10,
    /// No credential is stored under this id.
    CredentialNotFound = 11,
    /// Only the credential's issuer or the protocol admin may revoke it.
    NotCredentialIssuer = 12,
    /// The credential is already revoked.
    CredentialAlreadyRevoked = 13,
}
