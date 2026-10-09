#![no_std]
//! # MediTrust credentials
//!
//! Non-transferable ("soulbound") health-compliance credentials on Stellar
//! Soroban, minted only against a zero-knowledge attestation that a student
//! completed an accredited HIPAA/GDPR curriculum.
//!
//! ## Design in one paragraph
//!
//! A training provider generates an UltraHonk proof that some off-chain student
//! record satisfies a registered program. The proof carries exactly one public
//! input: a digest over a canonical [`CredentialStatement`] naming this contract,
//! the subject's wallet, the issuer, the program, an opaque commitment to the
//! student record, a single-use nullifier and an expiry. [`MediTrustCredentials::issue_credential`]
//! recomputes that digest, rejects any proof bound to a different statement, asks
//! the configured verifier contract to check it, and only then mints a credential
//! that is permanently bound to `subject`.
//!
//! ## Privacy properties
//!
//! * No personal data, government id, or training record is stored on-chain.
//! * The on-chain record contains only an opaque `subject_commitment`, so a
//!   credential can be proven about later without revealing the student record.
//! * Credentials are keyed by wallet and have no transfer entrypoint.
//!
//! ## Non-goals / caveats
//!
//! See `docs/security-model.md`. In short: the upstream UltraHonk verifier is
//! non-ZK (`UltraKeccakFlavor`), so witness data must never be treated as secret,
//! and issuance authority is an admin-managed allowlist.

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

mod binding;
mod error;
mod events;
mod types;
mod verifier;

#[cfg(test)]
mod test;

use binding::public_inputs as derive_public_inputs;
pub use binding::{domain, CredentialStatement, DOMAIN_TAG};
pub use error::Error;
pub use types::{Config, Credential, CredentialStatus, DataKey, Program, Standard};
pub use verifier::ProofVerifierClient;

use events::{
    AdminTransferred, CredentialIssued, CredentialRevoked, IssuerAllowed, IssuerDenied,
    ProgramRegistered, ProgramStatusChanged, VerifierUpdated,
};

// ---------------------------------------------------------------------------
// Storage lifetime management
//
// Ledgers close roughly every 5 seconds.
// ---------------------------------------------------------------------------

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 7;
const INSTANCE_TTL_EXTEND_TO: u32 = DAY_IN_LEDGERS * 30;
const PERSISTENT_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 30;
const PERSISTENT_TTL_EXTEND_TO: u32 = DAY_IN_LEDGERS * 365;

#[contract]
pub struct MediTrustCredentials;

#[contractimpl]
impl MediTrustCredentials {
    /// Configures the protocol.
    ///
    /// * `admin` — manages the issuer allowlist, the program registry and the
    ///   verifier address.
    /// * `verifier` — address of a contract implementing the `ProofVerifier`
    ///   interface (see `meditrust-verifier`).
    pub fn __constructor(env: Env, admin: Address, verifier: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Config) {
            return Err(Error::AlreadyInitialized);
        }
        let config = Config { admin, verifier };
        env.storage().instance().set(&DataKey::Config, &config);
        bump_instance(&env);
        Ok(())
    }

    // -- Administration -----------------------------------------------------

    /// Transfers protocol administration to `new_admin`.
    pub fn transfer_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), Error> {
        let mut config = require_admin(&env, &caller)?;
        let previous = config.admin.clone();
        config.admin = new_admin.clone();
        env.storage().instance().set(&DataKey::Config, &config);
        AdminTransferred {
            previous_admin: previous,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Adds a training provider to the issuance allowlist.
    pub fn allow_issuer(env: Env, caller: Address, issuer: Address) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        let key = DataKey::Issuer(issuer.clone());
        env.storage().persistent().set(&key, &true);
        bump_persistent(&env, &key);
        IssuerAllowed { issuer }.publish(&env);
        Ok(())
    }

    /// Removes a training provider from the issuance allowlist.
    ///
    /// Already-issued credentials are not deleted; they evaluate to
    /// [`CredentialStatus::IssuerDisabled`] until the issuer is reinstated.
    pub fn deny_issuer(env: Env, caller: Address, issuer: Address) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        let key = DataKey::Issuer(issuer.clone());
        env.storage().persistent().remove(&key);
        IssuerDenied { issuer }.publish(&env);
        Ok(())
    }

    /// Registers (or updates) a training program.
    pub fn register_program(
        env: Env,
        caller: Address,
        program_id: BytesN<32>,
        standard: Standard,
    ) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        let program = Program {
            id: program_id.clone(),
            standard,
            active: true,
        };
        let key = DataKey::Program(program_id.clone());
        env.storage().persistent().set(&key, &program);
        bump_persistent(&env, &key);
        ProgramRegistered {
            program_id,
            standard,
            active: true,
        }
        .publish(&env);
        Ok(())
    }

    /// Suspends or reinstates a training program.
    pub fn set_program_active(
        env: Env,
        caller: Address,
        program_id: BytesN<32>,
        active: bool,
    ) -> Result<(), Error> {
        require_admin(&env, &caller)?;
        let key = DataKey::Program(program_id.clone());
        let mut program: Program = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::ProgramNotRegistered)?;
        program.active = active;
        env.storage().persistent().set(&key, &program);
        bump_persistent(&env, &key);
        ProgramStatusChanged { program_id, active }.publish(&env);
        Ok(())
    }

    /// Points the protocol at a new verifier contract.
    pub fn set_verifier(env: Env, caller: Address, verifier: Address) -> Result<(), Error> {
        let mut config = require_admin(&env, &caller)?;
        config.verifier = verifier.clone();
        env.storage().instance().set(&DataKey::Config, &config);
        VerifierUpdated { verifier }.publish(&env);
        Ok(())
    }

    // -- Issuance -----------------------------------------------------------

    /// Mints a credential to `subject`, gated on a zero-knowledge attestation.
    ///
    /// Requirements, checked in order:
    ///
    /// 1. `issuer` authorises the call and is on the allowlist.
    /// 2. The attestation nullifier has not been consumed before.
    /// 3. `program_id` is registered and active.
    /// 4. `expires_at` is in the future.
    /// 5. `public_inputs` equals the canonical digest for exactly this statement.
    /// 6. The configured verifier accepts `proof` for those public inputs.
    ///
    /// Returns the credential id, which is the statement digest.
    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        program_id: BytesN<32>,
        subject_commitment: BytesN<32>,
        nullifier: BytesN<32>,
        expires_at: u64,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> Result<BytesN<32>, Error> {
        issuer.require_auth();
        let config = load_config(&env)?;
        bump_instance(&env);

        // Cheap, unauthenticated-looking checks first: never spend proof
        // verification budget on an attestation that can never be accepted.
        let nullifier_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(Error::NullifierAlreadyUsed);
        }

        if !is_issuer(&env, &issuer) {
            return Err(Error::IssuerNotAuthorized);
        }

        let program: Program = env
            .storage()
            .persistent()
            .get(&DataKey::Program(program_id.clone()))
            .ok_or(Error::ProgramNotRegistered)?;
        if !program.active {
            return Err(Error::ProgramSuspended);
        }

        let now = env.ledger().timestamp();
        if expires_at <= now {
            return Err(Error::InvalidExpiry);
        }

        let statement = CredentialStatement {
            domain: domain(&env),
            contract: env.current_contract_address(),
            subject: subject.clone(),
            issuer: issuer.clone(),
            program_id: program_id.clone(),
            subject_commitment: subject_commitment.clone(),
            nullifier: nullifier.clone(),
            expires_at,
        };

        // Bind the proof to this exact statement. Without this the verifier would
        // accept a proof for any statement, since UltraKeccakFlavor proofs carry
        // no submitter binding of their own.
        if derive_public_inputs(&env, &statement) != public_inputs {
            return Err(Error::PublicInputMismatch);
        }

        // Fail closed: a false result and a trapped verifier are both rejection.
        let client = ProofVerifierClient::new(&env, &config.verifier);
        if !matches!(
            client.try_verify_proof(&public_inputs, &proof),
            Ok(Ok(true))
        ) {
            return Err(Error::ProofVerificationFailed);
        }
        let verification_key_hash = match client.try_verification_key_hash() {
            Ok(Ok(hash)) => hash,
            _ => return Err(Error::ProofVerificationFailed),
        };

        let id = statement.digest(&env);
        let credential = Credential {
            id: id.clone(),
            subject: subject.clone(),
            issuer: issuer.clone(),
            program_id: program_id.clone(),
            standard: program.standard,
            subject_commitment,
            nullifier: nullifier.clone(),
            issued_at: now,
            expires_at,
            revoked: false,
            verification_key_hash,
        };

        let credential_key = DataKey::Credential(id.clone());
        env.storage().persistent().set(&credential_key, &credential);
        bump_persistent(&env, &credential_key);

        env.storage().persistent().set(&nullifier_key, &true);
        bump_persistent(&env, &nullifier_key);

        let subjects_key = DataKey::SubjectCredentials(subject.clone());
        let mut owned: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&subjects_key)
            .unwrap_or_else(|| Vec::new(&env));
        owned.push_back(id.clone());
        env.storage().persistent().set(&subjects_key, &owned);
        bump_persistent(&env, &subjects_key);

        CredentialIssued {
            subject,
            issuer,
            credential_id: id.clone(),
            program_id,
            standard: program.standard,
            subject_commitment: credential.subject_commitment.clone(),
            expires_at,
        }
        .publish(&env);

        Ok(id)
    }

    /// Revokes a credential. Callable by the issuing provider or the admin.
    ///
    /// Revocation is permanent; there is no un-revoke.
    pub fn revoke_credential(
        env: Env,
        caller: Address,
        credential_id: BytesN<32>,
    ) -> Result<(), Error> {
        caller.require_auth();
        let config = load_config(&env)?;

        let key = DataKey::Credential(credential_id.clone());
        let mut credential: Credential = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::CredentialNotFound)?;

        if caller != credential.issuer && caller != config.admin {
            return Err(Error::NotCredentialIssuer);
        }
        if credential.revoked {
            return Err(Error::CredentialAlreadyRevoked);
        }

        credential.revoked = true;
        env.storage().persistent().set(&key, &credential);
        bump_persistent(&env, &key);

        CredentialRevoked {
            subject: credential.subject,
            revoked_by: caller,
            credential_id,
        }
        .publish(&env);

        Ok(())
    }

    // -- Views --------------------------------------------------------------

    /// Loads a credential by id.
    pub fn get_credential(env: Env, credential_id: BytesN<32>) -> Result<Credential, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .ok_or(Error::CredentialNotFound)
    }

    /// Evaluates a credential against current ledger state.
    pub fn credential_status(env: Env, credential_id: BytesN<32>) -> CredentialStatus {
        let credential: Credential = match env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
        {
            Some(credential) => credential,
            None => return CredentialStatus::NotFound,
        };

        if credential.revoked {
            return CredentialStatus::Revoked;
        }
        if env.ledger().timestamp() >= credential.expires_at {
            return CredentialStatus::Expired;
        }
        if !is_issuer(&env, &credential.issuer) {
            return CredentialStatus::IssuerDisabled;
        }
        match env
            .storage()
            .persistent()
            .get::<DataKey, Program>(&DataKey::Program(credential.program_id.clone()))
        {
            Some(program) if program.active => CredentialStatus::Valid,
            Some(_) => CredentialStatus::ProgramSuspended,
            // A credential whose program registration has gone away is not safe
            // to treat as valid.
            None => CredentialStatus::ProgramSuspended,
        }
    }

    /// `true` only when the credential is currently [`CredentialStatus::Valid`].
    pub fn is_valid(env: Env, credential_id: BytesN<32>) -> bool {
        Self::credential_status(env, credential_id) == CredentialStatus::Valid
    }

    /// Convenience check for employers and medical boards: does `subject` hold a
    /// currently valid credential for `program_id`?
    ///
    /// Reveals nothing beyond a boolean and does not disclose which credential
    /// matched.
    pub fn is_valid_for(env: Env, subject: Address, program_id: BytesN<32>) -> bool {
        let owned: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
            .unwrap_or_else(|| Vec::new(&env));

        for id in owned.iter() {
            if credential_program(&env, &id) != Some(program_id.clone()) {
                continue;
            }
            if Self::credential_status(env.clone(), id) == CredentialStatus::Valid {
                return true;
            }
        }
        false
    }

    /// The opaque commitment a credential binds to, for off-chain
    /// proof-of-credential presentation.
    pub fn subject_commitment_of(env: Env, credential_id: BytesN<32>) -> Result<BytesN<32>, Error> {
        env.storage()
            .persistent()
            .get::<DataKey, Credential>(&DataKey::Credential(credential_id))
            .map(|credential| credential.subject_commitment)
            .ok_or(Error::CredentialNotFound)
    }

    /// Every credential id held by `subject`, including revoked and expired ones.
    pub fn credentials_of(env: Env, subject: Address) -> Vec<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Whether `issuer` may currently mint credentials.
    pub fn is_issuer(env: Env, issuer: Address) -> bool {
        is_issuer(&env, &issuer)
    }

    /// Metadata for a registered program.
    pub fn get_program(env: Env, program_id: BytesN<32>) -> Result<Program, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Program(program_id))
            .ok_or(Error::ProgramNotRegistered)
    }

    /// The protocol admin.
    pub fn admin(env: Env) -> Result<Address, Error> {
        load_config(&env).map(|config| config.admin)
    }

    /// The configured verifier contract.
    pub fn verifier(env: Env) -> Result<Address, Error> {
        load_config(&env).map(|config| config.verifier)
    }

    /// The single canonical public input for a statement.
    ///
    /// Exposed so issuers can build the exact `public_inputs` their proof must be
    /// generated against, and so wallets can audit the binding.
    pub fn issuance_public_inputs(
        env: Env,
        issuer: Address,
        subject: Address,
        program_id: BytesN<32>,
        subject_commitment: BytesN<32>,
        nullifier: BytesN<32>,
        expires_at: u64,
    ) -> Bytes {
        let statement = CredentialStatement {
            domain: domain(&env),
            contract: env.current_contract_address(),
            subject,
            issuer,
            program_id,
            subject_commitment,
            nullifier,
            expires_at,
        };
        derive_public_inputs(&env, &statement)
    }

    /// Soulbound marker. Credentials have no transfer entrypoint and are keyed to
    /// one wallet for their whole lifetime; wallets and explorers can use this to
    /// display the correct semantics.
    pub fn non_transferable(_env: Env) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn load_config(env: &Env) -> Result<Config, Error> {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .ok_or(Error::NotInitialized)
}

fn require_admin(env: &Env, caller: &Address) -> Result<Config, Error> {
    caller.require_auth();
    let config = load_config(env)?;
    if caller != &config.admin {
        return Err(Error::NotAdmin);
    }
    bump_instance(env);
    Ok(config)
}

fn is_issuer(env: &Env, issuer: &Address) -> bool {
    env.storage()
        .persistent()
        .get::<DataKey, bool>(&DataKey::Issuer(issuer.clone()))
        .unwrap_or(false)
}

fn credential_program(env: &Env, credential_id: &BytesN<32>) -> Option<BytesN<32>> {
    env.storage()
        .persistent()
        .get::<DataKey, Credential>(&DataKey::Credential(credential_id.clone()))
        .map(|credential| credential.program_id)
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

fn bump_persistent(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND_TO);
}
