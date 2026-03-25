package dev.fifthpower.pqc.legacy;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Simulates a typical government/enterprise signing service.
 *
 * This is the kind of code found in production systems today:
 * a private key stored in a KeyStore (or HSM), used for ECDSA signing.
 * The private key is tightly coupled to the algorithm — migrating to
 * a new algorithm means generating a new key, re-enrolling, and
 * updating every relying party.
 */
public class LegacySigningService {

    private final PrivateKey privateKey;
    private final PublicKey  publicKey;
    private final String     algorithm;

    public LegacySigningService(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey  = publicKey;
        this.algorithm  = "SHA256withECDSA";
    }

    /** Sign a document / message. */
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /** Verify a signature. */
    public boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    public PublicKey getPublicKey() { return publicKey; }

    public String getAlgorithm() { return algorithm; }

    // ── Factory ──

    /** Create a service with a fresh EC key pair (secp256r1). */
    public static LegacySigningService create() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        return new LegacySigningService(kp.getPrivate(), kp.getPublic());
    }

    /** Create a service from an existing key pair. */
    public static LegacySigningService fromKeyPair(KeyPair kp) {
        return new LegacySigningService(kp.getPrivate(), kp.getPublic());
    }
}
