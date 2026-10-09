use soroban_sdk::contracterror;

/// Errors surfaced by the verifier contract.
///
/// Every variant is a *rejection*. The contract never fails open: an unparsable
/// verification key, an unparsable proof, or an uninitialised contract all
/// resolve to "not verified".
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    /// The contract constructor has already run; the key is immutable.
    AlreadyInitialized = 1,
    /// An empty verification key was supplied.
    EmptyVerificationKey = 2,
    /// The verification key could not be parsed as an UltraHonk verification key.
    InvalidVerificationKey = 3,
    /// No verification key has been set on this contract instance.
    NotInitialized = 4,
}
