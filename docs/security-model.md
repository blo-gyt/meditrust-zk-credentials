# Security model

> **This code has not been audited.** The UltraHonk verifier crate it depends on was audited by
> OpenZeppelin (31 August 2026, commit `661db07`: no Critical/High/Medium findings), but the
> credential protocol in this repository has not.

## Trust assumptions

| Actor | Trusted for | Enforcement |
| --- | --- | --- |
| Protocol admin | Issuer allowlist, program registry, verifier address, revocation | `require_auth` on every admin entrypoint |
| Training provider (issuer) | Truthfulness of the training record behind a proof | Allowlisted by the admin; can only issue for registered programs; can be removed |
| Verifier contract | Correct evaluation of the pinned circuit | Immutable key, fail-closed results, pinned per credential by hash |
| Stellar / Soroban | Ledger integrity, auth, time | Protocol-level |

The admin is the strongest trust point. A compromised admin can allowlist a malicious provider or
point the protocol at a permissive verifier. `transfer_admin` allows rotation but there is no
multisig or timelock — see "Hardening roadmap".

## What the zero-knowledge layer does and does not provide

### Provided

* **Policy integrity.** A credential can only be minted if a proof verifies against the pinned
  verification key for the canonical public input. A buggy or hostile provider cannot mint a
  credential that does not satisfy the circuit.
* **Statement binding.** The proof is bound to this contract, this subject, this issuer, this
  program, this commitment, this nullifier and this expiry. A proof is a single-use, single-purpose
  object.
* **Replay protection.** A consumed nullifier can never be reused, so one training attestation
  yields at most one credential.
* **No personal data on-chain.** The record holds a wallet address and opaque hashes.

### Not provided — read this carefully

The upstream verifier implements UltraHonk's **non-zero-knowledge `UltraKeccakFlavor`**. Its own
README states it "provides no witness-hiding guarantee", that a proof "carries witness-dependent
protocol messages", and that on-chain wrappers accept the full proof as public transaction input.
`UltraZKFlavor` is **not** implemented upstream.

Therefore:

* **Circuit private inputs are not secret.** Anyone who sees the transaction can see the proof. Do
  not place a national ID, medical record, diagnosis or any regulated identifier in the witness.
  The circuit's private inputs must be limited to values whose disclosure is acceptable, or the
  protocol must be combined with off-chain presentation.
* **The proof is a public object.** Treat proof bytes as public data.
* **Proof bytes are not identifiers.** Upstream notes that an active prover can vary fixed-slot
  padding, so distinct byte strings can verify for one statement. Never key deduplication,
  replay protection or nullifiers on raw proof bytes. This implementation does not: it keys them on
  a contract-supplied nullifier and the statement digest.
* **The proof does not bind to the submitter.** Binding is reconstructed by the contract via the
  statement digest, as described above.
* **Wallet unlinkability is absent.** A credential is permanently bound to one wallet. Verifying it
  reveals which wallet was queried. Proving "I hold a credential" without naming the wallet is not
  implemented.

The honest summary: this design uses the proof system for **integrity and policy enforcement**, and
gets **confidentiality from what is left off-chain**, not from the proof's zero-knowledge property.

## Threat model

| Attack | Mitigation | Test |
| --- | --- | --- |
| Replay an accepted proof for a second credential | Nullifier consumed once, ever | `rejects_a_replayed_attestation_nullifier`, `rejects_a_byte_identical_replay` |
| Steal a proof and mint it to a different wallet | `subject` is in the statement digest | `rejects_public_inputs_bound_to_another_subject` |
| Replay a proof against a second deployment | Contract address is in the statement digest | `a_proof_for_one_deployment_cannot_be_replayed_on_another` |
| Extend a credential's validity by tampering with `expires_at` | `expires_at` is in the statement digest | `public_inputs_are_bound_to_the_exact_statement` |
| Issue without an accredited provider | Issuer allowlist, authenticated | `rejects_an_issuer_outside_the_allowlist` |
| Issue under an unregistered or suspended curriculum | Program registry | `rejects_an_unregistered_program`, `rejects_a_suspended_program` |
| Malformed `public_inputs` | Byte-exact equality with the derived digest | `rejects_public_inputs_of_the_wrong_length` |
| Make the verifier return `true` by trapping or erroring | Fail-closed on `false` *and* on a trapped call | `rejects_when_the_verifier_traps`, `rejects_a_proof_the_verifier_declines` |
| Deploy a verifier that can never verify | Key parsed eagerly at construction | `constructor_rejects_an_empty_key`, `constructor_rejects_a_malformed_key` |
| Grief an issuer by burning its nullifiers | Only an allowlisted issuer can consume one | `rejected_issuer_consumes_no_nullifier` |
| Revoke someone else's credential | Auth restricted to the issuing provider or admin | `unrelated_accounts_cannot_revoke` |
| Third party denies a credential that is still valid | Status is evaluated live against issuer/program standing | `denying_an_issuer_invalidates_its_outstanding_credentials` |
| Keep using a credential after the provider is struck off | `IssuerDisabled` status | `denying_an_issuer_invalidates_its_outstanding_credentials` |

## Failure behaviour

Verification is fail-closed, but *how* it fails depends on the cause:

* **The verifier returns `false`, or a deployed verifier contract traps** — `try_verify_proof`
  yields an error and `issue_credential` returns `ProofVerificationFailed` (error 10). Covered by
  `rejects_a_proof_the_verifier_declines` and `rejects_when_the_verifier_traps`.
* **The configured verifier address is not a contract at all** — the host traps the invocation
  before the contract can translate it, so the whole transaction aborts with
  `Error(Object, InvalidInput): not a contract address` rather than a clean
  `ProofVerificationFailed`. Observed on a local Standalone network. Nothing is minted and no
  nullifier is consumed (confirmed on-chain), so the security property holds, but operators should
  expect an opaque host error rather than error 10 when a verifier address is misconfigured.
* **Every failure is atomic.** The credential, its nullifier and the subject index are written only
  after verification succeeds, so a rejected issuance leaves no partial state.

Ordering matters for cost, not just correctness: the nullifier, allowlist and program checks all
run *before* the proof check, so a call that can never succeed never spends verification budget.

## Accepted trade-offs

* **No subject co-signature.** A provider can mint a credential onto any wallet without the holder's
  consent. This matches how certificates are normally issued, but it allows unsolicited credentials
  to be pushed to a wallet. The holder is not harmed: they can ignore it, and no data about them is
  written. An opt-in `accept` flow is on the roadmap.
* **Allowlist, not permissionless.** Issuance requires admin approval. This is the right default for
  a regulated credential, but it is a centralisation point.
* **Status is live, not snapshotted.** Removing an issuer retroactively invalidates its outstanding
  credentials. `deny_issuer` is therefore a recall mechanism, not just an onboarding control, and
  reinstating the issuer restores them.
* **`credentials_of` grows unbounded per wallet.** Each issuance appends to a vector. Fine at
  realistic volumes; a very large per-wallet history would make `is_valid_for` linear.
* **Verifier address is admin-trusted.** A malicious verifier accepts anything. Mitigated by
  `VerifierUpdated` events and the recorded `verification_key_hash`.

## Hardening roadmap

1. **Real zero-knowledge.** Move to a proving system/flavour with witness hiding (`UltraZKFlavor` is
   not implemented upstream today) so witness contents can be trusted with sensitive data.
   Alternatively, check `verifier.exists()` before the call so a misconfigured address produces
   error 10 instead of a host trap.
2. **Governance.** Replace the single admin with M-of-N medical-board approval for issuer and
   verifier changes, plus a timelock.
3. **Unlinkable presentation.** Let a holder prove "I hold a valid credential for program X" via a
   derived proof, instead of querying `is_valid_for(wallet, program)`.
4. **Recursive/proof-of-proof credentials.** Bind the credential to a `Poseidon` commitment and
   support a presentation proof over it.
5. **`max_validity` policy.** Bound how far in the future `expires_at` may be set.
6. **Storage growth.** Replace the per-wallet vector with paged indexing if histories grow large.
