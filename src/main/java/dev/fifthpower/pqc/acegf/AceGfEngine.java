package dev.fifthpower.pqc.acegf;

import java.security.KeyPair;
import java.util.List;

/**
 * ACE-GF Engine — the core interface for seed-storage-free identity.
 *
 * <h3>Key properties</h3>
 * <ul>
 *   <li><b>Seed-storage-free:</b> The identity root (REV) exists only
 *       ephemerally in memory and is never persisted.</li>
 *   <li><b>Deterministic reconstruction:</b> The REV is reconstructed
 *       from a Sealed Artifact + credential on every use.</li>
 *   <li><b>Context-isolated derivation:</b> Keys derived under distinct
 *       {@link CryptoContext}s are cryptographically independent.</li>
 *   <li><b>Cryptographic agility:</b> Adding a PQC algorithm = adding
 *       a new context.  No changes to the identity root or sealed artifact.</li>
 * </ul>
 *
 * <h3>wei_to_crypto_entity (SA-Migration)</h3>
 * <p>The {@link #weiToCryptoEntity} method encapsulates a legacy private key
 * into a Sealed Artifact.  The derivation router preserves original addresses
 * for legacy contexts while enabling new PQC contexts — zero asset movement,
 * zero identity change.</p>
 *
 * @see <a href="https://arxiv.org/abs/2511.20505">ACE-GF Paper</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-wang-acegf-protocol/">IETF I-D</a>
 */
public interface AceGfEngine {

    // ── Lifecycle ──

    /**
     * Create a new ACE-GF identity.
     * Generates a fresh 256-bit REV, seals it under the given credential,
     * and returns the Sealed Artifact.  The REV is zeroized before return.
     */
    SealedArtifact createIdentity(String credential);

    /**
     * Import a legacy private key via SA-Migration (wei_to_crypto_entity).
     *
     * <p>The legacy key is encapsulated into the Sealed Artifact format.
     * When keys are later derived with the original algorithm context,
     * the derivation router replays the legacy derivation — producing
     * the exact same public key / address.  New contexts (e.g. ML-DSA)
     * use HKDF derivation from the identity root.</p>
     *
     * @param legacyKeyPair  the existing key pair to import
     * @param credential     passphrase for sealing
     * @return Sealed Artifact containing the encapsulated legacy key
     */
    SealedArtifact weiToCryptoEntity(KeyPair legacyKeyPair, String credential);

    // ── Key Derivation ──

    /**
     * Derive a key pair under the given context.
     *
     * <p>Internally: Unseal → reconstruct REV → HKDF-Expand(REV, ctx) → key.
     * The REV and all intermediates are zeroized before return.</p>
     */
    DerivedKeyPair deriveKey(SealedArtifact sa, String credential, CryptoContext ctx);

    /**
     * Derive multiple key pairs in a single unseal operation.
     * More efficient than calling {@link #deriveKey} repeatedly.
     */
    List<DerivedKeyPair> deriveKeys(SealedArtifact sa, String credential,
                                    List<CryptoContext> contexts);

    // ── Credential Management ──

    /**
     * Rotate the sealing credential without changing the identity.
     * The REV is re-sealed under the new credential; all derived keys
     * remain identical.
     */
    SealedArtifact rotateCredential(SealedArtifact sa,
                                     String oldCredential,
                                     String newCredential);

    /**
     * Revoke authorization by destroying the credential binding.
     * After this call, the Sealed Artifact can no longer be unsealed.
     */
    void revoke(SealedArtifact sa, String credential);

    // ── Query ──

    /** List all algorithm IDs that this engine supports. */
    List<String> supportedAlgorithms();
}
