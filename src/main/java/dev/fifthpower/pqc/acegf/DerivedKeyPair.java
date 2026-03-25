package dev.fifthpower.pqc.acegf;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A key pair derived from an ACE-GF identity under a specific
 * {@link CryptoContext}.  The private key is ephemeral and should
 * be zeroized after use.
 */
public interface DerivedKeyPair {

    /** The context under which this key was derived. */
    CryptoContext context();

    /** JCA PrivateKey (ECDSA, ML-DSA, etc.). */
    PrivateKey privateKey();

    /** JCA PublicKey. */
    PublicKey publicKey();

    /** Algorithm name suitable for {@code Signature.getInstance()}. */
    String signatureAlgorithm();

    /** Zeroize the private key material from memory. */
    void zeroize();
}
