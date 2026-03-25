package dev.fifthpower.pqc.acegf;

/**
 * A derivation context that uniquely identifies a key within the ACE-GF
 * identity.  Keys derived under distinct contexts are cryptographically
 * independent — compromise of one does not affect others.
 *
 * @param algId   Algorithm identifier (e.g. "ecdsa-p256", "ml-dsa-44")
 * @param domain  Application domain  (e.g. "signing", "encryption")
 * @param index   Key index within the domain (for key rotation / fan-out)
 */
public record CryptoContext(String algId, String domain, int index) {

    /** Encode as the HKDF info string: "algId|domain|index" */
    public byte[] encode() {
        return "%s|%s|%d".formatted(algId, domain, index)
                         .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ── Predefined contexts ──

    public static CryptoContext ecdsaP256(int index) {
        return new CryptoContext("ecdsa-p256", "signing", index);
    }

    public static CryptoContext mlDsa44(int index) {
        return new CryptoContext("ml-dsa-44", "signing", index);
    }

    public static CryptoContext mlKem768(int index) {
        return new CryptoContext("ml-kem-768", "encryption", index);
    }

    public static CryptoContext x25519(int index) {
        return new CryptoContext("x25519", "key-agreement", index);
    }
}
