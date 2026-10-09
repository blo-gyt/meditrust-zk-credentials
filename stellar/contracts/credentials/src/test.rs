//! Unit tests for the credential protocol.
//!
//! ## Why a mock verifier
//!
//! A *valid* UltraHonk proof can only be produced by `nargo` + `bb` against the
//! compiled circuit. This suite therefore exercises the protocol against a mock
//! verifier contract that answers with a fixed verdict, which is exactly the
//! boundary the credential contract depends on: it never parses proofs itself.
//! Real end-to-end proof verification is covered by
//! `stellar/contracts/verifier/tests/ultrahonk_artifacts.rs`, which runs against
//! genuine artifacts when they are supplied.

use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, InvokeError,
};

use crate::{CredentialStatus, Error, MediTrustCredentials, MediTrustCredentialsClient, Standard};

// ---------------------------------------------------------------------------
// Mock verifiers
// ---------------------------------------------------------------------------

/// Answers every proof check with a fixed verdict supplied at deploy time.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn __constructor(env: Env, accept: bool) {
        env.storage()
            .instance()
            .set(&symbol_short!("accept"), &accept);
    }

    pub fn verify_proof(env: Env, _public_inputs: Bytes, _proof: Bytes) -> bool {
        env.storage()
            .instance()
            .get(&symbol_short!("accept"))
            .unwrap_or(false)
    }

    pub fn verification_key_hash(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &[0x7au8; 32])
    }
}

/// A hostile verifier that traps instead of returning a verdict. The credential
/// contract must treat this as a rejection rather than an accepted proof.
#[contract]
pub struct TrapVerifier;

#[contractimpl]
impl TrapVerifier {
    pub fn __constructor(_env: Env) {}

    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) -> bool {
        panic!("verifier trapped")
    }

    pub fn verification_key_hash(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &[0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts a contract error from a `try_*` client result.
///
/// The SDK wraps fallible calls as
/// `Result<Result<T, T::Error>, Result<ContractError, InvokeError>>`, so a
/// contract-level failure appears as `Err(Ok(error))`.
fn contract_error<T, C>(result: Result<Result<T, C>, Result<Error, InvokeError>>) -> Option<Error> {
    match result {
        Err(Ok(error)) => Some(error),
        _ => None,
    }
}

fn id(env: &Env, tag: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = tag;
    BytesN::from_array(env, &bytes)
}

struct Ctx<'a> {
    env: &'a Env,
    client: MediTrustCredentialsClient<'a>,
    admin: Address,
    issuer: Address,
    stranger: Address,
    subject: Address,
    other_subject: Address,
    hipaa_program: BytesN<32>,
}

impl<'a> Ctx<'a> {
    fn new(env: &'a Env, verifier: Address) -> Self {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let issuer = Address::generate(env);
        let stranger = Address::generate(env);
        let subject = Address::generate(env);
        let other_subject = Address::generate(env);

        let contract_id = env.register(MediTrustCredentials, (&admin, &verifier));
        let client = MediTrustCredentialsClient::new(env, &contract_id);

        let hipaa_program = id(env, 1);
        client.register_program(&admin, &hipaa_program, &Standard::Hipaa);
        client.allow_issuer(&admin, &issuer);

        Self {
            env,
            client,
            admin,
            issuer,
            stranger,
            subject,
            other_subject,
            hipaa_program,
        }
    }

    fn public_inputs(
        &self,
        issuer: &Address,
        subject: &Address,
        commitment: &BytesN<32>,
        nullifier: &BytesN<32>,
        expires_at: u64,
    ) -> Bytes {
        self.client.issuance_public_inputs(
            issuer,
            subject,
            &self.hipaa_program,
            commitment,
            nullifier,
            &expires_at,
        )
    }

    /// Issues a credential with a well-formed statement and a proof the mock
    /// verifier will accept (or reject, per its constructor flag).
    fn issue(
        &self,
        subject: &Address,
        commitment_tag: u8,
        nullifier_tag: u8,
    ) -> Result<BytesN<32>, Error> {
        let commitment = id(self.env, commitment_tag);
        let nullifier = id(self.env, nullifier_tag);
        let expires_at = self.env.ledger().timestamp() + 86_400;
        let public_inputs =
            self.public_inputs(&self.issuer, subject, &commitment, &nullifier, expires_at);
        let proof = Bytes::from_slice(self.env, &[0xabu8; 128]);

        match self.client.try_issue_credential(
            &self.issuer,
            subject,
            &self.hipaa_program,
            &commitment,
            &nullifier,
            &expires_at,
            &public_inputs,
            &proof,
        ) {
            Ok(Ok(credential_id)) => Ok(credential_id),
            Err(Ok(error)) => Err(error),
            _ => panic!("unexpected verifier invocation failure"),
        }
    }
}

fn mock(env: &Env, accept: bool) -> Address {
    env.register(MockVerifier, (&accept,))
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn issues_and_reports_a_valid_credential() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    assert!(ctx.client.is_valid(&credential_id));
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::Valid
    );

    let credential = ctx.client.get_credential(&credential_id);
    assert_eq!(credential.subject, ctx.subject);
    assert_eq!(credential.issuer, ctx.issuer);
    assert_eq!(credential.program_id, ctx.hipaa_program);
    assert_eq!(credential.standard, Standard::Hipaa);
    assert_eq!(credential.subject_commitment, id(&env, 2));
    assert_eq!(credential.nullifier, id(&env, 3));
    assert!(!credential.revoked);
    // The circuit that attested issuance is recorded for auditability.
    assert_eq!(
        credential.verification_key_hash,
        BytesN::from_array(&env, &[0x7au8; 32])
    );
}

#[test]
fn credential_id_is_the_statement_digest_and_is_deterministic() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let first = ctx.issue(&ctx.subject, 2, 3).unwrap();
    // Identical statement but a fresh nullifier gives a different credential.
    let second = ctx.issue(&ctx.subject, 2, 4).unwrap();
    assert_ne!(first, second);

    let credential = ctx.client.get_credential(&first);
    assert_eq!(credential.id, first);
}

#[test]
fn credentials_are_indexed_by_subject() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let first = ctx.issue(&ctx.subject, 2, 3).unwrap();
    let second = ctx.issue(&ctx.subject, 4, 5).unwrap();
    ctx.issue(&ctx.other_subject, 6, 7).unwrap();

    let owned = ctx.client.credentials_of(&ctx.subject);
    assert_eq!(owned.len(), 2);
    assert_eq!(owned.get(0).unwrap(), first);
    assert_eq!(owned.get(1).unwrap(), second);
    assert_eq!(ctx.client.credentials_of(&ctx.other_subject).len(), 1);
}

#[test]
fn credentials_are_declared_non_transferable() {
    // There is intentionally no transfer entrypoint; the marker lets wallets and
    // explorers render soulbound semantics.
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    assert!(ctx.client.non_transferable());
}

#[test]
fn is_valid_for_is_scoped_to_subject_and_program() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    ctx.issue(&ctx.subject, 2, 3).unwrap();

    assert!(ctx.client.is_valid_for(&ctx.subject, &ctx.hipaa_program));
    // A different wallet does not inherit the credential.
    assert!(!ctx
        .client
        .is_valid_for(&ctx.other_subject, &ctx.hipaa_program));
    // A different program is not satisfied by a HIPAA credential.
    assert!(!ctx.client.is_valid_for(&ctx.subject, &id(&env, 9)));
}

// ---------------------------------------------------------------------------
// Statement binding
// ---------------------------------------------------------------------------

#[test]
fn public_inputs_are_bound_to_the_exact_statement() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;

    let for_subject = ctx.public_inputs(
        &ctx.issuer,
        &ctx.subject,
        &commitment,
        &nullifier,
        expires_at,
    );
    let for_other = ctx.public_inputs(
        &ctx.issuer,
        &ctx.other_subject,
        &commitment,
        &nullifier,
        expires_at,
    );
    assert_ne!(
        for_subject, for_other,
        "changing the subject must change the statement digest"
    );

    let later_expiry =
        ctx.public_inputs(&ctx.issuer, &ctx.subject, &commitment, &nullifier, 172_800);
    assert_ne!(for_subject, later_expiry);

    // The derived input is a canonical single 32-byte BN254 scalar: the top byte
    // is zeroed so the value can never exceed the field modulus.
    assert_eq!(for_subject.len(), 32);
    assert_eq!(for_subject.get(0).unwrap(), 0x00);
}

#[test]
fn rejects_public_inputs_bound_to_another_subject() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;
    // Public inputs for a *different* subject: a stolen proof could never pass.
    let public_inputs = ctx.public_inputs(
        &ctx.issuer,
        &ctx.other_subject,
        &commitment,
        &nullifier,
        expires_at,
    );

    let result = ctx.client.try_issue_credential(
        &ctx.issuer,
        &ctx.subject,
        &ctx.hipaa_program,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    assert_eq!(contract_error(result), Some(Error::PublicInputMismatch));
}

#[test]
fn rejects_public_inputs_of_the_wrong_length() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let result = ctx.client.try_issue_credential(
        &ctx.issuer,
        &ctx.subject,
        &ctx.hipaa_program,
        &id(&env, 2),
        &id(&env, 3),
        &86_400,
        &Bytes::from_slice(&env, &[0u8; 31]),
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    assert_eq!(contract_error(result), Some(Error::PublicInputMismatch));
}

// ---------------------------------------------------------------------------
// Verification is fail-closed
// ---------------------------------------------------------------------------

#[test]
fn rejects_a_proof_the_verifier_declines() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, false));

    let result = ctx.issue(&ctx.subject, 2, 3);
    assert_eq!(result.err(), Some(Error::ProofVerificationFailed));
    assert_eq!(ctx.client.credentials_of(&ctx.subject).len(), 0);
}

#[test]
fn rejects_when_the_verifier_traps() {
    let env = Env::default();
    let verifier = env.register(TrapVerifier, ());
    let ctx = Ctx::new(&env, verifier);

    let result = ctx.issue(&ctx.subject, 2, 3);
    assert_eq!(result.err(), Some(Error::ProofVerificationFailed));
}

#[test]
fn verifier_is_swappable_by_the_admin() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let rejecting = mock(&env, false);

    ctx.client.set_verifier(&ctx.admin, &rejecting);
    assert_eq!(ctx.client.verifier(), rejecting);

    let result = ctx.issue(&ctx.subject, 2, 3);
    assert_eq!(result.err(), Some(Error::ProofVerificationFailed));
}

#[test]
fn non_admin_cannot_swap_the_verifier() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let result = ctx
        .client
        .try_set_verifier(&ctx.stranger, &mock(&env, true));
    assert_eq!(contract_error(result), Some(Error::NotAdmin));
}

// ---------------------------------------------------------------------------
// Issuance authorization and program registry
// ---------------------------------------------------------------------------

#[test]
fn rejects_an_issuer_outside_the_allowlist() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;
    // Self-consistent statement, but signed by someone who may not issue.
    let public_inputs = ctx.public_inputs(
        &ctx.stranger,
        &ctx.subject,
        &commitment,
        &nullifier,
        expires_at,
    );

    let result = ctx.client.try_issue_credential(
        &ctx.stranger,
        &ctx.subject,
        &ctx.hipaa_program,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    assert_eq!(contract_error(result), Some(Error::IssuerNotAuthorized));
}

#[test]
fn rejected_issuer_consumes_no_nullifier() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;
    let public_inputs = ctx.public_inputs(
        &ctx.stranger,
        &ctx.subject,
        &commitment,
        &nullifier,
        expires_at,
    );
    let proof = Bytes::from_slice(&env, &[0xabu8; 128]);

    let _ = ctx.client.try_issue_credential(
        &ctx.stranger,
        &ctx.subject,
        &ctx.hipaa_program,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &proof,
    );
    // The legitimate issuer can still use the same attestation nullifier.
    let accepted = ctx.issue(&ctx.subject, 2, 3);
    assert!(accepted.is_ok());
}

#[test]
fn rejects_an_unregistered_program() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let unknown = id(&env, 42);

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;
    let public_inputs = ctx.client.issuance_public_inputs(
        &ctx.issuer,
        &ctx.subject,
        &unknown,
        &commitment,
        &nullifier,
        &expires_at,
    );

    let result = ctx.client.try_issue_credential(
        &ctx.issuer,
        &ctx.subject,
        &unknown,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    assert_eq!(contract_error(result), Some(Error::ProgramNotRegistered));
}

#[test]
fn rejects_a_suspended_program() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    ctx.client
        .set_program_active(&ctx.admin, &ctx.hipaa_program, &false);

    let result = ctx.issue(&ctx.subject, 2, 3);
    assert_eq!(result.err(), Some(Error::ProgramSuspended));
}

#[test]
fn rejects_an_expiry_in_the_past() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 0; // ledger timestamp is 0 at the start of a test
    let public_inputs = ctx.public_inputs(
        &ctx.issuer,
        &ctx.subject,
        &commitment,
        &nullifier,
        expires_at,
    );

    let result = ctx.client.try_issue_credential(
        &ctx.issuer,
        &ctx.subject,
        &ctx.hipaa_program,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    assert_eq!(contract_error(result), Some(Error::InvalidExpiry));
}

#[test]
fn non_admin_cannot_manage_the_registry() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    assert_eq!(
        contract_error(ctx.client.try_allow_issuer(&ctx.stranger, &ctx.stranger)),
        Some(Error::NotAdmin)
    );
    assert_eq!(
        contract_error(ctx.client.try_deny_issuer(&ctx.stranger, &ctx.issuer)),
        Some(Error::NotAdmin)
    );
    assert_eq!(
        contract_error(ctx.client.try_register_program(
            &ctx.stranger,
            &id(&env, 77),
            &Standard::Gdpr
        )),
        Some(Error::NotAdmin)
    );
    assert_eq!(
        contract_error(ctx.client.try_set_program_active(
            &ctx.stranger,
            &ctx.hipaa_program,
            &false
        )),
        Some(Error::NotAdmin)
    );
}

#[test]
fn admin_can_transfer_administration() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    ctx.client.transfer_admin(&ctx.admin, &ctx.stranger);
    assert_eq!(ctx.client.admin(), ctx.stranger);
    // The previous admin has lost its privileges.
    assert_eq!(
        contract_error(ctx.client.try_allow_issuer(&ctx.admin, &ctx.admin)),
        Some(Error::NotAdmin)
    );
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

#[test]
fn rejects_a_replayed_attestation_nullifier() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    assert!(ctx.issue(&ctx.subject, 2, 3).is_ok());
    // Same nullifier, different commitment: a second credential from the same
    // underlying training attestation is refused.
    let result = ctx.issue(&ctx.subject, 9, 3);
    assert_eq!(result.err(), Some(Error::NullifierAlreadyUsed));
}

#[test]
fn rejects_a_byte_identical_replay() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let first = ctx.issue(&ctx.subject, 2, 3).unwrap();
    let result = ctx.issue(&ctx.subject, 2, 3);
    assert_eq!(result.err(), Some(Error::NullifierAlreadyUsed));
    assert_eq!(ctx.client.credentials_of(&ctx.subject).len(), 1);
    assert!(ctx.client.is_valid(&first));
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn issuer_can_revoke_its_own_credential() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    ctx.client.revoke_credential(&ctx.issuer, &credential_id);

    assert!(!ctx.client.is_valid(&credential_id));
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::Revoked
    );
    assert!(ctx.client.get_credential(&credential_id).revoked);
}

#[test]
fn admin_can_revoke_any_credential() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    ctx.client.revoke_credential(&ctx.admin, &credential_id);
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::Revoked
    );
}

#[test]
fn unrelated_accounts_cannot_revoke() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    let result = ctx
        .client
        .try_revoke_credential(&ctx.stranger, &credential_id);
    assert_eq!(contract_error(result), Some(Error::NotCredentialIssuer));

    // Even the credential holder cannot revoke on the issuer's behalf.
    let result = ctx
        .client
        .try_revoke_credential(&ctx.subject, &credential_id);
    assert_eq!(contract_error(result), Some(Error::NotCredentialIssuer));

    assert!(ctx.client.is_valid(&credential_id));
}

#[test]
fn revocation_is_permanent() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    ctx.client.revoke_credential(&ctx.issuer, &credential_id);
    let result = ctx
        .client
        .try_revoke_credential(&ctx.issuer, &credential_id);
    assert_eq!(
        contract_error(result),
        Some(Error::CredentialAlreadyRevoked)
    );
}

#[test]
fn revoking_an_unknown_credential_fails() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let result = ctx
        .client
        .try_revoke_credential(&ctx.issuer, &id(&env, 200));
    assert_eq!(contract_error(result), Some(Error::CredentialNotFound));
}

// ---------------------------------------------------------------------------
// Expiry and standing
// ---------------------------------------------------------------------------

#[test]
fn credentials_expire() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    let expires_at = ctx.client.get_credential(&credential_id).expires_at;
    env.ledger().set_timestamp(expires_at);
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::Expired
    );
    assert!(!ctx.client.is_valid(&credential_id));
    assert!(!ctx.client.is_valid_for(&ctx.subject, &ctx.hipaa_program));

    // Expiry is not revocation: the record is untouched.
    assert!(!ctx.client.get_credential(&credential_id).revoked);
}

#[test]
fn denying_an_issuer_invalidates_its_outstanding_credentials() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();
    assert!(ctx.client.is_valid(&credential_id));

    ctx.client.deny_issuer(&ctx.admin, &ctx.issuer);
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::IssuerDisabled
    );

    // Reinstating the provider restores its credentials.
    ctx.client.allow_issuer(&ctx.admin, &ctx.issuer);
    assert!(ctx.client.is_valid(&credential_id));
}

#[test]
fn suspending_a_program_invalidates_its_credentials() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    ctx.client
        .set_program_active(&ctx.admin, &ctx.hipaa_program, &false);
    assert_eq!(
        ctx.client.credential_status(&credential_id),
        CredentialStatus::ProgramSuspended
    );

    ctx.client
        .set_program_active(&ctx.admin, &ctx.hipaa_program, &true);
    assert!(ctx.client.is_valid(&credential_id));
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[test]
fn unknown_credentials_report_not_found() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let unknown = id(&env, 200);

    assert_eq!(
        ctx.client.credential_status(&unknown),
        CredentialStatus::NotFound
    );
    assert!(!ctx.client.is_valid(&unknown));
    assert_eq!(
        contract_error(ctx.client.try_get_credential(&unknown)),
        Some(Error::CredentialNotFound)
    );
    assert_eq!(
        contract_error(ctx.client.try_subject_commitment_of(&unknown)),
        Some(Error::CredentialNotFound)
    );
}

#[test]
fn subject_commitment_is_exposed_for_off_chain_presentation() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));
    let credential_id = ctx.issue(&ctx.subject, 2, 3).unwrap();

    assert_eq!(
        ctx.client.subject_commitment_of(&credential_id),
        id(&env, 2)
    );
}

#[test]
fn program_metadata_is_readable() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    let program = ctx.client.get_program(&ctx.hipaa_program);
    assert_eq!(program.id, ctx.hipaa_program);
    assert_eq!(program.standard, Standard::Hipaa);
    assert!(program.active);

    assert_eq!(
        contract_error(ctx.client.try_get_program(&id(&env, 42))),
        Some(Error::ProgramNotRegistered)
    );
}

#[test]
fn issuer_allowlist_is_readable() {
    let env = Env::default();
    let ctx = Ctx::new(&env, mock(&env, true));

    assert!(ctx.client.is_issuer(&ctx.issuer));
    assert!(!ctx.client.is_issuer(&ctx.stranger));

    ctx.client.deny_issuer(&ctx.admin, &ctx.issuer);
    assert!(!ctx.client.is_issuer(&ctx.issuer));
}

#[test]
fn configuration_is_readable() {
    let env = Env::default();
    let verifier = mock(&env, true);
    let ctx = Ctx::new(&env, verifier.clone());

    assert_eq!(ctx.client.admin(), ctx.admin);
    assert_eq!(ctx.client.verifier(), verifier);
}

// ---------------------------------------------------------------------------
// Independent deployments are isolated
// ---------------------------------------------------------------------------

#[test]
fn a_proof_for_one_deployment_cannot_be_replayed_on_another() {
    let env = Env::default();
    let first = Ctx::new(&env, mock(&env, true));

    // A second deployment with the same admin/verifier, i.e. the same contract
    // code but a different contract address.
    let second_client = MediTrustCredentialsClient::new(
        &env,
        &env.register(MediTrustCredentials, (&first.admin, &mock(&env, true))),
    );
    second_client.register_program(&first.admin, &first.hipaa_program, &Standard::Hipaa);
    second_client.allow_issuer(&first.admin, &first.issuer);

    let commitment = id(&env, 2);
    let nullifier = id(&env, 3);
    let expires_at = 86_400;
    // Public inputs derived for the *first* deployment.
    let public_inputs = first.public_inputs(
        &first.issuer,
        &first.subject,
        &commitment,
        &nullifier,
        expires_at,
    );

    let result = second_client.try_issue_credential(
        &first.issuer,
        &first.subject,
        &first.hipaa_program,
        &commitment,
        &nullifier,
        &expires_at,
        &public_inputs,
        &Bytes::from_slice(&env, &[0xabu8; 128]),
    );

    // The statement names the contract, so a cross-deployment replay is refused.
    assert_eq!(contract_error(result), Some(Error::PublicInputMismatch));
}
