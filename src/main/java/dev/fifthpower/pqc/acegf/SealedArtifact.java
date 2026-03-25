package dev.fifthpower.pqc.acegf;

/**
 * The Sealed Artifact (SA) — the only persistent object in ACE-GF.
 *
 * Contains the REV (identity root) encrypted under AES-GCM-SIV with a
 * key derived from the user's credential via Argon2id.  No secret
 * material is stored at rest; the REV exists only ephemerally in memory
 * during Unseal and is zeroized immediately after key derivation.
 */
public interface SealedArtifact {

    /** The ciphertext bytes (opaque to callers). */
    byte[] ciphertext();

    /** Salt used for Argon2id key derivation. */
    byte[] salt();

    /** Whether this artifact originated from a legacy key import. */
    boolean isLegacyImport();
}
