//! Protocol events.
//!
//! Indexers can reconstruct the full credential graph from these alone. Events
//! carry no personal data — only wallet addresses, opaque commitments and
//! identifiers.

use soroban_sdk::{contractevent, Address, BytesN};

use crate::types::Standard;

/// A credential was minted. Emitted only after proof verification succeeds.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialIssued {
    #[topic]
    pub subject: Address,
    #[topic]
    pub issuer: Address,
    pub credential_id: BytesN<32>,
    pub program_id: BytesN<32>,
    pub standard: Standard,
    pub subject_commitment: BytesN<32>,
    pub expires_at: u64,
}

/// A credential was revoked by its issuer or the admin.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub subject: Address,
    #[topic]
    pub revoked_by: Address,
    pub credential_id: BytesN<32>,
}

/// A training provider was added to the issuance allowlist.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAllowed {
    #[topic]
    pub issuer: Address,
}

/// A training provider was removed from the issuance allowlist.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerDenied {
    #[topic]
    pub issuer: Address,
}

/// A training program was registered or updated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramRegistered {
    #[topic]
    pub program_id: BytesN<32>,
    pub standard: Standard,
    pub active: bool,
}

/// A training program was suspended or reinstated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramStatusChanged {
    #[topic]
    pub program_id: BytesN<32>,
    pub active: bool,
}

/// The configured proof verifier changed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierUpdated {
    pub verifier: Address,
}

/// The protocol admin changed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferred {
    #[topic]
    pub previous_admin: Address,
    #[topic]
    pub new_admin: Address,
}
