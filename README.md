# meditrust-zk-credentials

A privacy-preserving healthcare education and credential verification protocol built on
[Stellar](https://stellar.org)'s [Soroban](https://developers.stellar.org/docs/build/smart-contracts)
platform.

Health workers and students complete HIPAA/GDPR compliance training and receive a
**non-transferable** credential in their Stellar wallet. Medical boards and employers can then
verify that a wallet holds a current safety clearance **without learning the holder's identity,
government ID, or training history** — the on-chain record contains no personal data, only an
opaque commitment.

Issuance is gated on a zero-knowledge proof: the contract mints a credential only after an
audited [UltraHonk](https://barretenberg.aztec.network/docs/learn/about_ultrahonk/) (Noir) verifier
accepts a proof bound to the exact issuance statement.

---

## Status

Working, tested Stellar/Soroban contract pair — not audited, not deployed to a public network.

| Check | Result |
| --- | --- |
| `cargo test --workspace` | 40 passing, 4 ignored (artifact-gated) |
| `cargo clippy --workspace --all-targets` | clean, no warnings |
| `cargo fmt --all -- --check` | clean |
| `stellar contract build` (both contracts) | wasm produced, see sizes below |

| Contract | Optimized wasm |
| --- | --- |
| `meditrust-credentials` | ~20.9 KB, 21 exported functions |
| `meditrust-verifier` | ~22.6 KB, 4 exported functions |

**Read [`docs/security-model.md`](docs/security-model.md) before using this for anything real.**
Two upstream properties materially limit the privacy claims; they are summarised below.

---

## Architecture

```
        off-chain                                on-chain (Soroban)
  ┌──────────────────────┐
  │ training provider    │
  │  nargo + bb prove    │
  │        │             │
  │        ▼             │
  │  proof + public      │            ┌────────────────────────────┐
  │  inputs              │            │  meditrust-credentials     │
  └────────┬─────────────┘            │                            │
           │  issue_credential(...)   │  · admin / issuer allowlist│
           └─────────────────────────▶│  · program registry        │
                                      │  · nullifier replay guard  │
   ┌──────────────────┐  verify_proof │  · non-transferable creds  │
   │ meditrust-       │◀──────────────│  · revocation · expiry     │
   │ verifier         │               └────────────────────────────┘
   │ UltraHonk (audit)│                          │
   └──────────────────┘                          ▼
                                        credential bound to `subject`
```

The credential contract never parses a proof. It talks to a verifier contract through a narrow
interface (`verify_proof(public_inputs, proof) -> bool`), so the proof system can be swapped, and
so the credential logic is unit-testable against a mock verifier.

### Proof/statement binding

The audited upstream verifier implements the `UltraKeccakFlavor` **only**, which does *not* bind a
proof to the transaction submitter and provides **no replay protection**
([crate README](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/README.md)).
Both properties are supplied by the credential contract instead.

Every proof must carry exactly one public input: a digest over a canonical
`CredentialStatement` naming the contract address, subject, issuer, program, commitment, nullifier
and expiry. `issue_credential` recomputes that digest and rejects anything else, so a proof is
only ever usable for the single statement it was generated for.

```
public_input = sha256(ScVal::XDR(statement))      // truncated to 31 bytes
                │                                  // left-padded with 0x00 so the value is
                ▼                                  // always a canonical BN254 scalar
statement = { domain, contract, subject, issuer,
              program_id, subject_commitment, nullifier, expires_at }
```

Consequences:

* **Replay** — a nullifier may be consumed once, ever.
* **Cross-subject theft** — swapping `subject` changes the digest, so the proof fails.
* **Cross-deployment replay** — the contract address is in the statement.
* **Expiry/commitment tampering** — both are in the statement.

---

## Repository layout

```
Cargo.toml                      workspace root
rust-toolchain.toml             Rust channel + wasm targets
Makefile                        common tasks
docs/
  architecture.md               components and data flow
  security-model.md             threat model, trust assumptions, known limitations
  zk-pipeline.md                circuit spec, artifact generation, verifier integration
stellar/
  contracts/
    credentials/                meditrust-credentials (the protocol)
      src/{lib,types,binding,verifier,events,error,test}.rs
    verifier/                   meditrust-verifier (UltraHonk wrapper)
      src/{lib,error,test}.rs
      tests/ultrahonk_artifacts.rs   artifact-gated end-to-end tests
```

---

## Quickstart

Requires Rust (see `rust-toolchain.toml`), the `wasm32v1-none` target, and
[Stellar CLI](https://github.com/stellar/stellar-cli) v25.2.0+.

```bash
# format, lint, test
make fmt-check
make clippy
make test

# build deployable wasm for both contracts
make build
```

### Deployment shape

```bash
# 1. Deploy the verifier first: it pins the circuit verification key permanently.
stellar contract deploy \
  --wasm target/wasm32v1-none/release/meditrust_verifier.wasm \
  --source <admin-key> --network <network> \
  -- --circuit_id meditrust-credential-v1 --verification_key-file-path vk

# 2. Deploy the credential contract pointed at that verifier.
stellar contract deploy \
  --wasm target/wasm32v1-none/release/meditrust_credentials.wasm \
  --source <admin-key> --network <network> \
  -- --admin <admin-address> --verifier <verifier-contract-id>

# 3. Register a program and authorise a training provider.
stellar contract invoke --id <credentials-id> --source <admin-key> --network <network> \
  -- register_program --caller <admin-address> --program_id <32-byte-id> --standard Hipaa
stellar contract invoke --id <credentials-id> --source <admin-key> --network <network> \
  -- allow_issuer --caller <admin-address> --issuer <provider-address>
```

The verification key is immutable once the verifier is deployed: rotating the circuit means
deploying a new verifier and pointing the credential contract at it with `set_verifier`, which
leaves previously issued credentials auditable via their stored `verification_key_hash`.

---

## Contract API

### `meditrust-credentials`

| Function | Auth | Purpose |
| --- | --- | --- |
| `__constructor(admin, verifier)` | — | Configure the protocol |
| `transfer_admin(caller, new_admin)` | admin | Hand over administration |
| `allow_issuer` / `deny_issuer` | admin | Training-provider allowlist |
| `register_program(program_id, standard)` | admin | Register a curriculum (`Hipaa`/`Gdpr`/`Other`) |
| `set_program_active(program_id, active)` | admin | Suspend or reinstate a program |
| `set_verifier(verifier)` | admin | Point at a new verifier contract |
| `issue_credential(issuer, subject, program_id, commitment, nullifier, expires_at, public_inputs, proof)` | issuer | Mint a credential, gated on a valid proof |
| `revoke_credential(caller, credential_id)` | issuer or admin | Revoke permanently |
| `get_credential`, `credential_status`, `is_valid`, `is_valid_for` | — | Reads |
| `credentials_of`, `subject_commitment_of`, `is_issuer`, `get_program` | — | Reads |
| `issuance_public_inputs(...)` | — | Derive the canonical public input for a statement |
| `admin`, `verifier`, `non_transferable` | — | Configuration and SBT marker |

`credential_status` returns `Valid`, `Revoked`, `Expired`, `IssuerDisabled`, `ProgramSuspended` or
`NotFound`. Credentials are deliberately **not** deleted when a provider is removed or a program
is suspended — the history stays verifiable.

### `meditrust-verifier`

| Function | Purpose |
| --- | --- |
| `__constructor(circuit_id, verification_key)` | Parse and pin a verification key; rejects unusable keys at deploy time |
| `verify_proof(public_inputs, proof)` | `true` only on a valid proof; never panics, never fails open |
| `verification_key_hash()` | `sha256` of the pinned key |
| `circuit_id()` | Identifier of the pinned circuit |

---

## Testing

```bash
make test        # unit suites; artifact-gated tests report as ignored
make test-all    # also runs the artifact-gated UltraHonk tests
```

* **`meditrust-credentials` (35 tests)** — full lifecycle against a mock verifier: issuance,
  statement binding, cross-subject/cross-deployment replay rejection, nullifier replay,
  unauthorized issuance, admin-only paths, revocation, expiry, issuer/program standing,
  and a hostile verifier that traps (which must fail closed).
* **`meditrust-verifier` (5 tests)** — deployment guards: empty, truncated, zero-filled and
  out-of-curve verification keys must all be rejected.
* **`tests/ultrahonk_artifacts.rs` (4 tests, ignored by default)** — real end-to-end proof
  verification. These need artifacts produced by `nargo` + `bb`; see
  [`docs/zk-pipeline.md`](docs/zk-pipeline.md).

```bash
MEDTRUST_ULTRAHONK_ARTIFACTS=circuits/credential_attestation/target \
  cargo test -p meditrust-verifier --test ultrahonk_artifacts -- --include-ignored
```

The `test_snapshots/` directories are written by `soroban-sdk` testutils and act as a regression
record of ledger-state changes; they are committed intentionally, so a state-layout change shows up
as a reviewable diff.

### Verified on a local network

The built wasm was deployed to a Stellar Standalone network and exercised through `stellar contract
invoke`: `register_program` and `allow_issuer` submitted and emitted their events, reads (`admin`,
`is_issuer`, `get_program`, `non_transferable`, `is_valid_for`, `credential_status`) returned the
expected values, a non-admin admin call was rejected with `Error(Contract, #3)`, tampered public
inputs were rejected with `Error(Contract, #9)`, and a failed issuance left `credentials_of` empty.
Deploying the verifier with a zero-filled verification key was rejected on-chain with
`Error(Contract, #3)` (`InvalidVerificationKey`), confirming the deploy-time key guard in a real
network rather than only under testutils.

Full UltraHonk proof verification requires real circuit artifacts, so the artifact-gated tests
remain untested here — see [`docs/zk-pipeline.md`](docs/zk-pipeline.md).

---

## Privacy properties and caveats

**What holds.** No personal data, government identifiers or training records are written on-chain.
The chain stores a wallet address, opaque identifiers, an issuance/expiry timestamp and a
commitment. Verification can answer "does this wallet hold a valid HIPAA clearance for program X?"
with a single boolean.

**What does not hold.** The upstream verifier implements UltraHonk's *non-zero-knowledge*
`UltraKeccakFlavor`. It provides no witness-hiding guarantee: proofs carry witness-dependent
protocol messages, and on-chain wrappers accept the proof as public transaction input. Therefore:

* Do not put data you need to keep secret in the circuit's private witness.
* Treat the proof bytes as public.
* A verifier is not a privacy technology on its own — it is an *integrity and policy* mechanism,
  and here it enforces "only training that satisfies the circuit can mint a credential" plus
  statement binding and replay protection.

Wallet-level unlinkability (proving "I have a credential" without revealing which wallet) is **not**
implemented; the credential is bound to one wallet by design, and `is_valid_for` reveals the
queried wallet. See [`docs/security-model.md`](docs/security-model.md) for the full threat model
and the roadmap towards a genuinely zero-knowledge flavour.

## License

MIT — see [LICENSE](LICENSE).
