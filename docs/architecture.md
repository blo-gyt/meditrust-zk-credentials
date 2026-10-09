# Architecture

## Components

### `meditrust-credentials`

The protocol contract. It holds all policy: who may issue, which curricula exist, which
credentials are live, and when a credential stops being valid.

It contains no cryptography beyond hashing. Every proof check is delegated across a contract call,
so the credential logic is independent of the proving system and can be tested against a mock.

### `meditrust-verifier`

A thin wrapper around the audited
[`ultrahonk_soroban_verifier`](https://github.com/NethermindEth/rs-soroban-ultrahonk) crate.

* The verification key is supplied at construction, parsed eagerly, and **immutable** thereafter.
  A deployer cannot accidentally ship a verifier that can never verify.
* `verify_proof` returns a plain `bool` and is total: a missing key, an unparsable key, a malformed
  proof or a failed check all return `false`. It never panics and never fails open.
* The credential contract reads `verification_key_hash()` after a successful check and records it
  on the credential, so an auditor can tell which circuit revision attested a given credential.

### Off-chain prover (not in this repository)

A training provider runs a Noir circuit through `nargo` and `bb` to produce a proof and its public
inputs. See [`zk-pipeline.md`](zk-pipeline.md) for the circuit specification, the exact public-input
derivation, and the toolchain versions.

## Data flow

```
student completes HIPAA module
        │
        ▼
provider builds witness ──▶ nargo + bb ──▶ proof, public_inputs
        │
        ▼
provider signs issue_credential(issuer, subject, program_id, commitment,
                                nullifier, expires_at, public_inputs, proof)
        │
        ├─ 1. issuer.require_auth()
        ├─ 2. nullifier unused?           (cheap, unauthenticated checks first)
        ├─ 3. issuer on allowlist?
        ├─ 4. program registered and active?
        ├─ 5. expires_at in the future?
        ├─ 6. public_inputs == sha256(XDR(statement))?     ← statement binding
        ├─ 7. verifier.verify_proof(public_inputs, proof)  ← cross-contract
        └─ 8. mint credential bound to `subject`, consume nullifier, emit event
```

Steps are ordered so that a call which can never succeed costs the least: the nullifier check and
the allowlist check happen before any proof verification budget is spent.

## On-chain data model

All entries are `persistent` storage except the configuration, which is `instance` storage.
TTLs are extended on every write (instance: 7 day threshold / 30 day extend; persistent: 30 day
threshold / 365 day extend).

| Key | Value | Notes |
| --- | --- | --- |
| `Config` | `{ admin, verifier }` | instance |
| `Issuer(Address)` | `bool` | allowlist membership |
| `Program(BytesN<32>)` | `Program { id, standard, active }` | curriculum registry |
| `Credential(BytesN<32>)` | `Credential` | keyed by statement digest |
| `SubjectCredentials(Address)` | `Vec<BytesN<32>>` | credential ids per wallet |
| `Nullifier(BytesN<32>)` | `bool` | consumed attestations |

### `Credential`

```rust
pub struct Credential {
    pub id: BytesN<32>,                    // = statement digest
    pub subject: Address,                  // immutable; no transfer path exists
    pub issuer: Address,
    pub program_id: BytesN<32>,
    pub standard: Standard,                // Hipaa | Gdpr | Other
    pub subject_commitment: BytesN<32>,    // opaque binding to off-chain records
    pub nullifier: BytesN<32>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub verification_key_hash: BytesN<32>, // which circuit attested this
}
```

There is no field that can hold a name, date of birth, national id, employer, or training score,
and there is no entrypoint that can set one.

## Why a separate verifier contract

1. **Swappability.** Circuit revisions and proving systems change. `set_verifier` moves the protocol
   forward without reissuing credentials, and old credentials keep the key hash that attested them.
2. **Testability.** The credential contract's tests drive a mock verifier, so the entire protocol
   is covered without needing to generate a proof.
3. **Blast radius.** The verifier holds no funds and no policy. It is a pure predicate.

The trade-off is one extra contract call per issuance. The admin-controlled verifier address is a
trust point: a malicious verifier could accept everything. Only the admin can set it, and every
change emits `VerifierUpdated`.

## Non-transferability

There is deliberately **no transfer entrypoint**, and `subject` is never mutated. Non-transferability
is therefore a property of the interface rather than a runtime check that could be bypassed.

`non_transferable()` returns a constant `true` so wallets and explorers can detect soulbound
semantics without simulating a transfer.

## Events

`CredentialIssued`, `CredentialRevoked`, `IssuerAllowed`, `IssuerDenied`, `ProgramRegistered`,
`ProgramStatusChanged`, `VerifierUpdated`, `AdminTransferred`.

Subject-bearing events topic on `subject` and `issuer`, so an indexer can reconstruct a wallet's
credential history from logs alone. Events carry no personal data.
