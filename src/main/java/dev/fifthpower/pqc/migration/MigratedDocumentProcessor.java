package dev.fifthpower.pqc.migration;

import dev.fifthpower.pqc.acegf.*;
import dev.fifthpower.pqc.acegf.CryptoContext;
import dev.fifthpower.pqc.acegf.CryptoEntitySigningService;
import dev.fifthpower.pqc.legacy.DocumentProcessor.SignedDocument;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Base64;

/**
 * The migrated version of DocumentProcessor.
 *
 * <p>This class demonstrates how an existing enterprise application can be
 * upgraded to post-quantum cryptography using ACE-GF, with <b>zero changes</b>
 * to the signing identity and <b>minimal code changes</b> to the business logic.</p>
 *
 * <h3>What changed vs the legacy version:</h3>
 * <ul>
 *   <li>Signing service: {@code LegacySigningService} → {@code CryptoEntitySigningService}</li>
 *   <li>Key storage: persistent private key → ephemeral derivation from Sealed Artifact</li>
 *   <li>Algorithm: ECDSA only → ECDSA + ML-DSA (phase-dependent)</li>
 * </ul>
 *
 * <h3>What did NOT change:</h3>
 * <ul>
 *   <li>Business logic (sign/verify flow)</li>
 *   <li>Public key identity (legacy ECDSA context preserves original key)</li>
 *   <li>Document format</li>
 *   <li>Any downstream system or relying party</li>
 * </ul>
 */
public class MigratedDocumentProcessor {

    private final CryptoEntitySigningService signingService;
    private final MigrationPlan              plan;

    public MigratedDocumentProcessor(CryptoEntitySigningService signingService,
                                      MigrationPlan plan) {
        this.signingService = signingService;
        this.plan           = plan;
    }

    /**
     * Sign a document according to the current migration phase.
     *
     * <ul>
     *   <li>CLASSICAL_ONLY → ECDSA signature only</li>
     *   <li>HYBRID         → ECDSA + ML-DSA dual signature</li>
     *   <li>PQC_PRIMARY    → ML-DSA primary + ECDSA secondary</li>
     *   <li>PQC_ONLY       → ML-DSA signature only</li>
     * </ul>
     */
    public MigratedSignedDocument signDocument(String documentId, byte[] content)
            throws GeneralSecurityException {

        return switch (plan.phase()) {

            case CLASSICAL_ONLY -> {
                byte[] sig = signingService.signClassical(content);
                yield new MigratedSignedDocument(
                        documentId, content, sig, null,
                        "SHA256withECDSA", null,
                        plan.phase(), Instant.now());
            }

            case HYBRID -> {
                var dual = signingService.dualSign(content);
                yield new MigratedSignedDocument(
                        documentId, content, dual.classical(), dual.postQuantum(),
                        "SHA256withECDSA", "ML-DSA-44",
                        plan.phase(), Instant.now());
            }

            case PQC_PRIMARY -> {
                var dual = signingService.dualSign(content);
                yield new MigratedSignedDocument(
                        documentId, content, dual.classical(), dual.postQuantum(),
                        "SHA256withECDSA", "ML-DSA-44",
                        plan.phase(), Instant.now());
            }

            case PQC_ONLY -> {
                byte[] sig = signingService.signPostQuantum(content);
                yield new MigratedSignedDocument(
                        documentId, content, null, sig,
                        null, "ML-DSA-44",
                        plan.phase(), Instant.now());
            }
        };
    }

    /**
     * Verify a document — automatically selects the appropriate algorithm
     * based on what signatures are present.
     */
    public VerificationResult verifyDocument(MigratedSignedDocument doc)
            throws GeneralSecurityException {

        boolean classicalOk = false;
        boolean pqcOk       = false;

        if (doc.classicalSignature() != null) {
            classicalOk = signingService.verify(
                    doc.content(), doc.classicalSignature(),
                    CryptoContext.ecdsaP256(0));
        }

        if (doc.pqcSignature() != null) {
            pqcOk = signingService.verify(
                    doc.content(), doc.pqcSignature(),
                    CryptoContext.mlDsa44(0));
        }

        return new VerificationResult(classicalOk, pqcOk, doc.phase());
    }

    // ── Result types ──

    public record MigratedSignedDocument(
            String               documentId,
            byte[]               content,
            byte[]               classicalSignature,
            byte[]               pqcSignature,
            String               classicalAlgorithm,
            String               pqcAlgorithm,
            MigrationPlan.Phase  phase,
            Instant              timestamp
    ) {
        @Override
        public String toString() {
            String cSig = classicalSignature != null
                    ? Base64.getEncoder().encodeToString(classicalSignature).substring(0, Math.min(16, Base64.getEncoder().encodeToString(classicalSignature).length())) + "..."
                    : "none";
            String pSig = pqcSignature != null
                    ? Base64.getEncoder().encodeToString(pqcSignature).substring(0, Math.min(16, Base64.getEncoder().encodeToString(pqcSignature).length())) + "..."
                    : "none";
            return "MigratedSignedDocument{id=%s, phase=%s, classical=%s, pqc=%s}"
                    .formatted(documentId, phase, cSig, pSig);
        }
    }

    public record VerificationResult(
            boolean             classicalValid,
            boolean             pqcValid,
            MigrationPlan.Phase phase
    ) {
        public boolean isValid() {
            return switch (phase) {
                case CLASSICAL_ONLY -> classicalValid;
                case HYBRID, PQC_PRIMARY -> classicalValid && pqcValid;
                case PQC_ONLY -> pqcValid;
            };
        }
    }
}
