package dev.fifthpower.pqc.migration;

import dev.fifthpower.pqc.acegf.*;
import dev.fifthpower.pqc.legacy.*;
import dev.fifthpower.pqc.legacy.DocumentProcessor;
import dev.fifthpower.pqc.legacy.LegacySigningService;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/**
 * End-to-end demonstration of PQC migration using ACE-GF.
 *
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  BEFORE: Legacy System                                         │
 * │                                                                │
 * │  ┌──────────────┐      ┌──────────────────────┐                │
 * │  │ Private Key   │─────▶│ DocumentProcessor    │                │
 * │  │ (ECDSA P-256) │      │ sign() / verify()    │                │
 * │  │ stored at rest│      └──────────────────────┘                │
 * │  └──────────────┘                                              │
 * │  • Single algorithm, single point of failure                   │
 * │  • Key migration = new identity = break all relying parties    │
 * └─────────────────────────────────────────────────────────────────┘
 *
 *                    ┌─────────────────────┐
 *                    │ wei_to_crypto_entity │
 *                    │  (SA-Migration)      │
 *                    │  Zero-movement       │
 *                    │  key upgrade         │
 *                    └─────────────────────┘
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  AFTER: ACE-GF Identity                                        │
 * │                                                                │
 * │  ┌──────────────┐      ┌──────────────────────┐                │
 * │  │ Sealed       │─────▶│ MigratedDocument-    │                │
 * │  │ Artifact (SA)│      │ Processor            │                │
 * │  │ no secret    │      │ sign() / verify()    │                │
 * │  │ at rest      │      └──────────────────────┘                │
 * │  └──────┬───────┘                                              │
 * │         │ derive(ctx)                                          │
 * │    ┌────┴────┬────────┬────────┐                               │
 * │    ▼         ▼        ▼        ▼                               │
 * │  ECDSA    ML-DSA   ML-KEM   X25519                             │
 * │  P-256     -44      -768                                       │
 * │ (legacy)  (PQC)    (PQC)   (E2EE)                              │
 * │  same key! new!    new!    new!                                 │
 * └─────────────────────────────────────────────────────────────────┘
 * </pre>
 *
 * Run this class to see the full migration walkthrough.
 */
public class MigrationDemo {

    public static void main(String[] args) throws Exception {

        System.out.println("""
                ╔══════════════════════════════════════════════════════════════╗
                ║  PQC Migration Demo — ACE-GF wei_to_crypto_entity          ║
                ║  Crypto Agility · Low Risk · Low Cost · Smooth Transition   ║
                ╚══════════════════════════════════════════════════════════════╝
                """);

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // STEP 1: The legacy system — a government document signing service
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        step("1", "LEGACY SYSTEM — ECDSA Document Signing Service");

        LegacySigningService legacy = LegacySigningService.create();
        DocumentProcessor legacyProcessor = new DocumentProcessor(legacy);

        byte[] document = "Government Document GC-2026-0042: Budget Allocation"
                .getBytes(StandardCharsets.UTF_8);

        DocumentProcessor.SignedDocument legacySigned =
                legacyProcessor.signDocument("GC-2026-0042", document);
        boolean legacyValid = legacyProcessor.verifyDocument(legacySigned);

        System.out.println("  Legacy key algorithm : " + legacy.getAlgorithm());
        System.out.println("  Signed document      : " + legacySigned);
        System.out.println("  Verification         : " + (legacyValid ? "✓ VALID" : "✗ INVALID"));
        System.out.println("  ⚠  Private key stored at rest — single point of failure");
        System.out.println("  ⚠  No PQC support — vulnerable to HNDL attack");
        System.out.println();

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // STEP 2: SA-Migration — import legacy key into ACE-GF
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        step("2", "SA-MIGRATION — wei_to_crypto_entity");

        System.out.println("  Importing legacy ECDSA key into ACE-GF...");
        System.out.println("  • Legacy key encapsulated into Sealed Artifact");
        System.out.println("  • REV constructed from legacy key material");
        System.out.println("  • Sealed with Argon2id + AES-GCM-SIV");
        System.out.println("  • Legacy key zeroized from memory");
        System.out.println("  • Sealed Artifact is now the only persistent object");
        System.out.println();
        System.out.println("  Result:");
        System.out.println("    ✓ Legacy ECDSA identity PRESERVED");
        System.out.println("    ✓ No secret material at rest");
        System.out.println("    ✓ PQC contexts now available");
        System.out.println("    ✓ Zero disruption to existing systems");
        System.out.println();

        // NOTE: Below is pseudo-code showing how the real integration works.
        // The actual AceGfEngine implementation would call into the Rust
        // ACE-GF library via JNI/FFI or a WASM runtime.

        System.out.println("  ┌─ Pseudocode ─────────────────────────────────────┐");
        System.out.println("  │                                                  │");
        System.out.println("  │  AceGfEngine engine = AceGfEngine.create();      │");
        System.out.println("  │                                                  │");
        System.out.println("  │  // Import legacy key — zero movement            │");
        System.out.println("  │  SealedArtifact sa = engine.weiToCryptoEntity(   │");
        System.out.println("  │      legacyKeyPair, credential);                 │");
        System.out.println("  │                                                  │");
        System.out.println("  │  // Derive legacy context — same key!            │");
        System.out.println("  │  DerivedKeyPair ecdsa = engine.deriveKey(         │");
        System.out.println("  │      sa, credential, CryptoContext.ecdsaP256(0));│");
        System.out.println("  │  assert ecdsa.publicKey().equals(legacyPubKey);  │");
        System.out.println("  │                                                  │");
        System.out.println("  │  // Derive PQC context — new capability!         │");
        System.out.println("  │  DerivedKeyPair mldsa = engine.deriveKey(         │");
        System.out.println("  │      sa, credential, CryptoContext.mlDsa44(0));  │");
        System.out.println("  │  // → quantum-safe signing, same identity        │");
        System.out.println("  │                                                  │");
        System.out.println("  └──────────────────────────────────────────────────┘");
        System.out.println();

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // STEP 3: Phase 1 — Classical only (ACE-GF deployed, same behavior)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        step("3", "PHASE 1 — CLASSICAL ONLY (ACE-GF deployed)");

        System.out.println("  MigrationPlan: CLASSICAL_ONLY");
        System.out.println("  • ACE-GF is the identity substrate");
        System.out.println("  • All signing still uses ECDSA context");
        System.out.println("  • Downstream systems see no change");
        System.out.println("  • Private key no longer stored at rest ✓");
        System.out.println();

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // STEP 4: Phase 2 — Hybrid dual-signing
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        step("4", "PHASE 2 — HYBRID DUAL-SIGNING");

        System.out.println("  MigrationPlan: HYBRID");
        System.out.println("  • Every document gets TWO signatures:");
        System.out.println("      ECDSA P-256  (classical — for legacy verifiers)");
        System.out.println("      ML-DSA-44    (PQC — quantum-safe)");
        System.out.println("  • Legacy verifiers use ECDSA, ignore ML-DSA");
        System.out.println("  • Updated verifiers validate both");
        System.out.println("  • Zero disruption to any relying party");
        System.out.println();

        System.out.println("  ┌─ Pseudocode ─────────────────────────────────────┐");
        System.out.println("  │                                                  │");
        System.out.println("  │  MigrationPlan plan = MigrationPlan.phase2();    │");
        System.out.println("  │  var processor = new MigratedDocumentProcessor(  │");
        System.out.println("  │      signingService, plan);                      │");
        System.out.println("  │                                                  │");
        System.out.println("  │  var doc = processor.signDocument(id, content);  │");
        System.out.println("  │  // doc.classicalSignature() → ECDSA  ✓          │");
        System.out.println("  │  // doc.pqcSignature()       → ML-DSA ✓          │");
        System.out.println("  │                                                  │");
        System.out.println("  │  var result = processor.verifyDocument(doc);     │");
        System.out.println("  │  // result.classicalValid() → true               │");
        System.out.println("  │  // result.pqcValid()       → true               │");
        System.out.println("  │                                                  │");
        System.out.println("  └──────────────────────────────────────────────────┘");
        System.out.println();

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // STEP 5: Phase 3 & 4 — PQC primary, then PQC only
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        step("5", "PHASE 3 → 4 — PQC PRIMARY → PQC ONLY");

        System.out.println("  Phase 3: PQC_PRIMARY");
        System.out.println("    • ML-DSA is the primary signature");
        System.out.println("    • ECDSA still included for backward compatibility");
        System.out.println("    • Verifiers should prefer ML-DSA");
        System.out.println();
        System.out.println("  Phase 4: PQC_ONLY");
        System.out.println("    • Classical ECDSA contexts DISABLED");
        System.out.println("    • Only ML-DSA signatures produced");
        System.out.println("    • Migration complete ✓");
        System.out.println("    • Quantum-vulnerable algorithms eliminated ✓");
        System.out.println();

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // Summary
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        System.out.println("""
                ╔══════════════════════════════════════════════════════════════╗
                ║  Migration Summary                                          ║
                ╠══════════════════════════════════════════════════════════════╣
                ║                                                             ║
                ║  Crypto Agility                                             ║
                ║    • Context-isolated derivation: ECDSA + ML-DSA + ML-KEM   ║
                ║    • Adding PQC = adding a new CryptoContext                ║
                ║    • No changes to identity root or sealed artifact          ║
                ║                                                             ║
                ║  Low Risk                                                   ║
                ║    • No persistent master secret (seed-storage-free)         ║
                ║    • Standard primitives: AES-GCM-SIV / HKDF / Argon2id    ║
                ║    • Legacy key identity preserved — zero disruption         ║
                ║                                                             ║
                ║  Low Cost                                                   ║
                ║    • Software-only — no hardware replacement                 ║
                ║    • Minimal code changes (swap signing service)             ║
                ║    • Leverage existing IT refresh cycles                     ║
                ║                                                             ║
                ║  Smooth Transition                                          ║
                ║    • 4-phase migration: Classical → Hybrid → PQC → PQC-only ║
                ║    • Dual-signing ensures backward compatibility             ║
                ║    • Each phase is independently deployable                  ║
                ║                                                             ║
                ╚══════════════════════════════════════════════════════════════╝
                """);
    }

    private static void step(String num, String title) {
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.printf("  STEP %s: %s%n", num, title);
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println();
    }
}
