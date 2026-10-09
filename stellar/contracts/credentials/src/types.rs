use soroban_sdk::{contracttype, Address, BytesN};

/// The regulatory training standard a credential attests to.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Standard {
    /// US HIPAA workforce privacy/security training.
    Hipaa,
    /// EU GDPR data-protection training.
    Gdpr,
    /// Any other accredited health-compliance curriculum.
    Other,
}

/// A registered training program. Administered by the protocol admin so that
/// issuers can only mint credentials for reviewed curricula.
#[contracttype]
#[derive(Clone)]
pub struct Program {
    pub id: BytesN<32>,
    pub standard: Standard,
    /// Suspended programs cannot be used for new issuance, but credentials
    /// already issued under them remain distinguishable (see
    /// [`CredentialStatus::ProgramSuspended`]).
    pub active: bool,
}

/// A non-transferable health-compliance credential.
///
/// The record stores no personal data: `subject_commitment` is an opaque
/// commitment to the holder's off-chain training record, and `subject` is the
/// wallet the credential is permanently bound to.
#[contracttype]
#[derive(Clone)]
pub struct Credential {
    /// `sha256` over the canonical issuance statement; also the storage key.
    pub id: BytesN<32>,
    /// Wallet the credential is bound to. Immutable — there is no transfer path.
    pub subject: Address,
    /// Training provider that issued the credential.
    pub issuer: Address,
    /// Registered program the credential was issued under.
    pub program_id: BytesN<32>,
    pub standard: Standard,
    /// Opaque commitment binding the credential to off-chain student records
    /// (e.g. `Poseidon(student_secret, issuer_salt)`).
    pub subject_commitment: BytesN<32>,
    /// Single-use attestation nullifier.
    pub nullifier: BytesN<32>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    /// `sha256` of the UltraHonk verification key that attested issuance. Lets a
    /// verifier tell which circuit revision a credential came from.
    pub verification_key_hash: BytesN<32>,
}

/// Outcome of evaluating a credential against current ledger state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStatus {
    /// Currently valid.
    Valid,
    /// Explicitly revoked by the issuer or the admin.
    Revoked,
    /// Past its `expires_at`.
    Expired,
    /// The issuing provider is no longer on the allowlist.
    IssuerDisabled,
    /// The program the credential was issued under is currently suspended.
    ProgramSuspended,
    /// No such credential.
    NotFound,
}

/// Storage keys.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract-wide configuration (instance storage).
    Config,
    /// Issuer allowlist membership (persistent).
    Issuer(Address),
    /// Registered training program (persistent).
    Program(BytesN<32>),
    /// Issued credential (persistent).
    Credential(BytesN<32>),
    /// Credential ids held by a subject (persistent).
    SubjectCredentials(Address),
    /// Consumed attestation nullifiers (persistent).
    Nullifier(BytesN<32>),
}

/// Contract-wide configuration.
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    /// Address of the proof verifier contract implementing the
    /// `ProofVerifier` interface.
    pub verifier: Address,
}
