# ZK pipeline

How a proof is produced off-chain and what the contract requires of it.

> **Status:** the circuit is specified here but **its source is not in this repository** and has not
> been compiled. Everything the *contracts* require of a proof is implemented and tested; producing
> the artifacts is the remaining step. No test in this repository has verified a genuine proof —
> the four artifact-gated tests are `#[ignore]`d until artifacts exist.

## Toolchain

Matching the upstream verifier crate:

| Tool | Version | Install |
| --- | --- | --- |
| Noir / `nargo` | `1.0.0-beta.9` | `noirup -v 1.0.0-beta.9` |
| Barretenberg / `bb` | `0.87.0` | `bbup -v 0.87.0` |
| Stellar CLI | `25.2.0+` | see the CLI releases page |
| Rust | see `rust-toolchain.toml` | `rustup` |

Proofs must be generated with the **Keccak transcript**, because the on-chain verifier implements
`UltraKeccakFlavor`:

```bash
bb prove --oracle_hash keccak ...
```

The verifier crate supports exactly this flavour — non-ZK, non-recursive. See
[`security-model.md`](security-model.md).

## Circuit: `credential_attestation`

### Statement

> "I know a student record that satisfies training program `program_id`, and the record was
> attested by `issuer`, and this attestation is being used exactly once for a credential bound to
> a statement digest `public_input`."

### Public input (exactly one)

```
public_input = sha256(ScVal::XDR(statement))[0..31] padded on the left with 0x00
```

The 32-byte, big-endian field element is derived from the statement:

```rust
pub struct CredentialStatement {
    pub domain: BytesN<32>,            // sha256("meditrust:health-credential:v1")
    pub contract: Address,             // the credential contract's own address
    pub subject: Address,              // wallet the credential is bound to
    pub issuer: Address,               // authorising training provider
    pub program_id: BytesN<32>,
    pub subject_commitment: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub expires_at: u64,
}
```

`ScVal::XDR` is the Soroban XDR encoding of the contract-type value, serialised exactly as the
`soroban-sdk` does it. A prover reproduces this by depending on `soroban-sdk` and calling
`soroban_sdk::xdr::ToXdr::to_xdr` on the same struct, then `sha256`.

The digest is truncated to 31 bytes and left-padded with `0x00` because UltraHonk public inputs must
be canonical BN254 scalars, and a raw 256-bit digest can exceed the field modulus. The result is
below `2^248`, so it is always canonical.

Off-chain, an issuer does not need to derive the digest themselves: the contract exposes

```bash
stellar contract invoke --id <credentials-id> --network <network> \
  -- issuance_public_inputs \
  --issuer <G...> --subject <G...> --program_id <hex> \
  --subject_commitment <hex> --nullifier <hex> --expires_at <unix-seconds>
```

which returns the exact 32-byte public input the proof must be generated against.

### Private witness (suggested)

* `student_secret` — holder's off-chain secret, preimage of `subject_commitment`
* `attestation` — the provider's signed statement that the curriculum was completed
* `issuer_pubkey` / issuer authorisation material
* `program_params` — e.g. required module set, completion date

**Reminder:** because the flavour is non-ZK, do not put regulated identifiers in the witness.
Constrain the witness to values whose disclosure is acceptable; use it to prove *properties* of the
record (completed, in-date, issued by an accredited provider), not to hide the record itself.

### Constraints (sketch)

1. `subject_commitment == Poseidon(student_secret, issuer_salt)`.
2. The attestation is valid under the authorised issuer for `program_id`.
3. `public_input ==` the digest computed from the statement fields listed above.
4. The attestation's completion timestamp is within the program's validity window and consistent
   with `expires_at`.

## Generating artifacts

```bash
cd circuits/credential_attestation
nargo compile
nargo execute            # produces the witness

bb write_vk -b target/credential_attestation.json -o target --oracle_hash keccak
bb prove   -b target/credential_attestation.json \
           -w target/credential_attestation.gz \
           -o target --oracle_hash keccak
```

The output folder holds exactly the three files the tests expect: `vk`, `proof`,
`public_inputs`.

## Verifying end-to-end

The four artifact-gated tests are `#[ignore]`d so a clean checkout stays green without the ZK
toolchain. Run them with the artifact directory:

```bash
MEDTRUST_ULTRAHONK_ARTIFACTS=circuits/credential_attestation/target \
  cargo test -p meditrust-verifier --test ultrahonk_artifacts -- --include-ignored
```

| Test | Asserts |
| --- | --- |
| `verifies_a_genuine_ultrahonk_proof` | The proof verifies and the verifier pins the exact key |
| `rejects_a_truncated_proof` | A malformed proof yields `false`, not a trap |
| `rejects_a_proof_against_tampered_public_inputs` | Changing a public input invalidates the proof |
| `rejects_a_corrupted_verification_key` | A corrupted key cannot be loaded, so it cannot be deployed |

To exercise the credential contract end-to-end with a real proof, use the deployed verifier and
call `issue_credential` with the public inputs returned by `issuance_public_inputs`.

## Cost notes

The verifier is the dominant cost of issuance: it re-derives the Fiat–Shamir transcript and runs
sumcheck plus Shplemini batch openings over BN254 for every check. Expect issuance to be
substantially more expensive than a plain state write. The verifier's key is stored in instance
storage and re-parsed on each call, which is the upstream reference pattern; a future optimisation
is caching the parsed key.
