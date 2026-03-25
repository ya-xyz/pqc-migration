package dev.fifthpower.pqc.acegf;

import dev.fifthpower.pqc.legacy.LegacySigningService;

import java.security.GeneralSecurityException;
import java.security.Signature;

/**
 * A signing service backed by an ACE-GF identity.
 *
 * <p>Unlike {@link LegacySigningService} which holds
 * a persistent private key, this service reconstructs the key ephemerally
 * on each operation from the Sealed Artifact + credential.</p>
 *
 * <p>The same identity can sign with <b>any</b> supported algorithm simply
 * by changing the {@link CryptoContext} — classical ECDSA and post-quantum
 * ML-DSA coexist under one identity root.</p>
 */
public class CryptoEntitySigningService {

    private final AceGfEngine    engine;
    private final SealedArtifact artifact;
    private final String         credential;

    public CryptoEntitySigningService(AceGfEngine engine,
                                       SealedArtifact artifact,
                                       String credential) {
        this.engine     = engine;
        this.artifact   = artifact;
        this.credential = credential;
    }

    /**
     * Sign data using the specified crypto context.
     *
     * <p>The private key is derived ephemerally, used once, then zeroized.</p>
     */
    public byte[] sign(byte[] data, CryptoContext ctx) throws GeneralSecurityException {
        DerivedKeyPair kp = engine.deriveKey(artifact, credential, ctx);
        try {
            Signature sig = Signature.getInstance(kp.signatureAlgorithm());
            sig.initSign(kp.privateKey());
            sig.update(data);
            return sig.sign();
        } finally {
            kp.zeroize();
        }
    }

    /**
     * Verify a signature using the specified crypto context.
     */
    public boolean verify(byte[] data, byte[] signature, CryptoContext ctx)
            throws GeneralSecurityException {
        DerivedKeyPair kp = engine.deriveKey(artifact, credential, ctx);
        try {
            Signature sig = Signature.getInstance(kp.signatureAlgorithm());
            sig.initVerify(kp.publicKey());
            sig.update(data);
            return sig.verify(signature);
        } finally {
            kp.zeroize();
        }
    }

    /** Sign with legacy-compatible ECDSA context. */
    public byte[] signClassical(byte[] data) throws GeneralSecurityException {
        return sign(data, CryptoContext.ecdsaP256(0));
    }

    /** Sign with post-quantum ML-DSA-44 context. */
    public byte[] signPostQuantum(byte[] data) throws GeneralSecurityException {
        return sign(data, CryptoContext.mlDsa44(0));
    }

    /**
     * Dual-sign: produce both a classical and a PQC signature.
     * Useful during the transition period when verifiers may not
     * yet support PQC.
     */
    public DualSignature dualSign(byte[] data) throws GeneralSecurityException {
        return new DualSignature(
                signClassical(data),
                signPostQuantum(data));
    }

    public record DualSignature(byte[] classical, byte[] postQuantum) {}
}
