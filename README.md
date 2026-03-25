# PQC Migration Demo — ACE-GF `wei_to_crypto_entity`

A working Java demonstration of how an existing enterprise signing system can migrate to post-quantum cryptography using [ACE-GF](https://arxiv.org/abs/2511.20505), with **zero disruption** to identity, infrastructure, or relying parties.

This project accompanies the proposal deck *"Smooth PQC Migration with ACE-GF"*.

## The Problem

Government and enterprise systems today rely on classical public-key cryptography (ECDSA, RSA) with persistent private keys. Migrating to PQC under current approaches requires:

- Generating new key pairs under a new algorithm
- Re-enrolling identities across all relying parties
- Replacing hardware (HSMs, smart cards)
- Running parallel infrastructure during transition

This is expensive, risky, and slow.

## The ACE-GF Solution

ACE-GF (Atomic Cryptographic Entity Generative Framework) resolves this through **context-isolated key derivation** from a single identity root:

```
                    ┌─────────────────────────────────┐
                    │       Sealed Artifact (SA)       │
                    │   (only persistent object —      │
                    │    no secret material at rest)    │
                    └────────────┬────────────────────┘
                                 │ Unseal (credential)
                                 ▼
                    ┌─────────────────────────────────┐
                    │   REV (Identity Root, ephemeral) │
                    └────────────┬────────────────────┘
                                 │ HKDF-SHA256 + Context
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │ ECDSA    │ │ ML-DSA   │ │ ML-KEM   │
              │ P-256    │ │ -44      │ │ -768     │
              │ (legacy) │ │ (PQC)    │ │ (PQC)    │
              │ same key!│ │ new!     │ │ new!     │
              └──────────┘ └──────────┘ └──────────┘
```

**Adding a PQC algorithm = adding a new `CryptoContext`. No changes to identity root, sealed artifact, or any downstream system.**

## Project Structure

```
src/main/java/dev/fifthpower/pqc/
├── legacy/                              # Simulated existing system
│   ├── LegacySigningService.java        # ECDSA signing with persistent private key
│   └── DocumentProcessor.java           # Business logic: sign & verify documents
│
├── acegf/                               # ACE-GF SDK interfaces
│   ├── AceGfEngine.java                 # Core engine (importLegacyKey, deriveKey)
│   ├── SealedArtifact.java              # The only persistent object
│   ├── DerivedKeyPair.java              # Ephemeral derived key pair
│   ├── CryptoContext.java               # Context-isolated derivation descriptor
│   └── CryptoEntitySigningService.java  # Signing service with dual-sign support
│
└── migration/                           # Migration layer
    ├── MigrationPlan.java               # 4-phase migration plan
    ├── MigratedDocumentProcessor.java   # Migrated document processor
    └── MigrationDemo.java              # Runnable end-to-end demonstration
```

### Layer 1: Legacy System (`legacy/`)

Simulates a typical government or financial institution's document signing service — an ECDSA private key stored in a keystore, used by a `DocumentProcessor` for signing and verification. This is the **before** state.

### Layer 2: ACE-GF Interfaces (`acegf/`)

Defines the ACE-GF SDK as Java interfaces. Key concepts:

| Interface | Role |
|-----------|------|
| `AceGfEngine` | Identity lifecycle: create, import legacy key, derive keys, rotate credentials, revoke |
| `SealedArtifact` | The encrypted identity container — no secret at rest |
| `DerivedKeyPair` | An ephemeral key pair derived under a specific `CryptoContext` |
| `CryptoContext` | `(algId, domain, index)` — ensures cryptographic isolation across algorithms |
| `CryptoEntitySigningService` | Drop-in replacement for `LegacySigningService` with multi-algorithm support |

The critical method is `AceGfEngine.importLegacyKey()` — this is the **`wei_to_crypto_entity`** (SA-Migration) operation that encapsulates a legacy key into the ACE-GF identity without changing its public key.

### Layer 3: Migration (`migration/`)

Implements the phased transition:

| Phase | `MigrationPlan.Phase` | Behavior |
|-------|-----------------------|----------|
| 1 | `CLASSICAL_ONLY` | ACE-GF deployed; all signing uses ECDSA context. No visible change to downstream. |
| 2 | `HYBRID` | Dual-sign: every document gets both ECDSA and ML-DSA signatures. Legacy verifiers use ECDSA; updated verifiers validate both. |
| 3 | `PQC_PRIMARY` | ML-DSA is primary; ECDSA included for backward compatibility. |
| 4 | `PQC_ONLY` | Classical contexts disabled. Full post-quantum operation. Migration complete. |

## Running the Demo

```bash
mvn compile exec:java -Dexec.mainClass="migration.dev.fifthpower.pqc.MigrationDemo"
```

Requires Java 17+ and Maven. The demo:
1. Creates a legacy ECDSA signing service and signs a document
2. Shows the SA-Migration (wei_to_crypto_entity) import flow
3. Walks through all four migration phases
4. Prints a migration summary

## What This Achieves

This demo proves that a real-world enterprise signing system can be upgraded to post-quantum cryptography with the following concrete results:

**Zero disruption.** The legacy ECDSA public key is **preserved exactly** after migration. No relying party, certificate chain, or downstream system needs to be updated during Phase 1 deployment. The `DocumentProcessor` business logic requires only a one-line change (swap the signing service).

**Immediate HNDL protection.** From Phase 2 onward, every signed document carries a post-quantum ML-DSA-44 signature alongside the classical ECDSA signature. Even if an adversary is harvesting encrypted traffic today, the PQC signature provides forward security against a future quantum computer.

**No hardware replacement.** The entire migration is software-only. ACE-GF runs on standard JVMs and commodity servers. It is compatible with HSMs and TPMs but does not require them — eliminating the most expensive line item in traditional PQC migration budgets.

**Eliminated single point of failure.** The legacy system stores a private key at rest — if compromised, the identity is permanently lost. After migration, the Sealed Artifact contains no secret material. The identity root (REV) exists only ephemerally in memory during signing operations and is zeroized immediately after use.

**One identity, unlimited algorithms.** The `CryptoContext` mechanism means the organization never needs to "migrate" again. When NIST standardizes new algorithms (e.g., SLH-DSA, BIKE), they are added as new contexts under the same identity — no re-keying, no re-enrollment, no infrastructure changes.

**Quantified cost savings.** Compared to traditional key replacement:

| Cost Category | Traditional Migration | ACE-GF SA-Migration |
|---|---|---|
| Key re-generation & enrollment | Weeks per system | Zero — identity preserved |
| Hardware (HSM/smart card replacement) | $5K–50K+ per device | $0 — software-only |
| Downtime during cutover | Hours to days | Zero — phased, no cutover |
| Relying party notification | All counterparties | None in Phase 1-2 |
| Risk of identity break | High (new keys) | Zero (same public key) |

## References

- **ACE-GF Paper**: [arXiv:2511.20505](https://arxiv.org/abs/2511.20505)
- **IETF Internet-Draft**: [draft-wang-acegf-protocol-00](https://datatracker.ietf.org/doc/draft-wang-acegf-protocol/)

## License

Copyright 2026 FifthPower Inc. All rights reserved.
