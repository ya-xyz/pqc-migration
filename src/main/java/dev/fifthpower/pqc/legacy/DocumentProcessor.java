package dev.fifthpower.pqc.legacy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Base64;

/**
 * A typical enterprise application that signs and verifies documents.
 *
 * This represents the kind of business logic found in government systems,
 * financial institutions, healthcare, etc. — anywhere documents must be
 * cryptographically signed for integrity and non-repudiation.
 *
 * The problem: this class is tightly coupled to LegacySigningService,
 * which uses ECDSA with a persistent private key. Migrating to PQC
 * requires changing the signing service — but the business logic should
 * remain untouched.
 */
public class DocumentProcessor {

    private final LegacySigningService signingService;

    public DocumentProcessor(LegacySigningService signingService) {
        this.signingService = signingService;
    }

    /** Sign a document, return a SignedDocument record. */
    public SignedDocument signDocument(String documentId, byte[] content)
            throws GeneralSecurityException {
        byte[] signature = signingService.sign(content);
        return new SignedDocument(
                documentId,
                content,
                signature,
                signingService.getAlgorithm(),
                signingService.getPublicKey().getEncoded(),
                Instant.now()
        );
    }

    /** Verify a previously signed document. */
    public boolean verifyDocument(SignedDocument doc) throws GeneralSecurityException {
        return signingService.verify(doc.content(), doc.signature());
    }

    public record SignedDocument(
            String  documentId,
            byte[]  content,
            byte[]  signature,
            String  algorithm,
            byte[]  signerPublicKey,
            Instant timestamp
    ) {
        @Override
        public String toString() {
            return "SignedDocument{id=%s, algo=%s, sig=%s, ts=%s}".formatted(
                    documentId, algorithm,
                    Base64.getEncoder().encodeToString(signature).substring(0, 20) + "...",
                    timestamp);
        }
    }
}
