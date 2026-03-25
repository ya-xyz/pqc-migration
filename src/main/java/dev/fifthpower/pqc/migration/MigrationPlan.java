package dev.fifthpower.pqc.migration;

/**
 * Describes the migration phase and configuration.
 *
 * <pre>
 * Phase 1 (CLASSICAL_ONLY):   Deploy ACE-GF, continue ECDSA signing
 * Phase 2 (HYBRID):           Dual-sign with ECDSA + ML-DSA
 * Phase 3 (PQC_PRIMARY):      ML-DSA is primary, ECDSA for backward compat
 * Phase 4 (PQC_ONLY):         ECDSA contexts disabled, full PQC
 * </pre>
 */
public record MigrationPlan(Phase phase, boolean dualSignEnabled) {

    public enum Phase {
        /** ACE-GF deployed; all signing uses classical ECDSA context. */
        CLASSICAL_ONLY,

        /** Dual-sign: every signature includes both ECDSA and ML-DSA. */
        HYBRID,

        /** ML-DSA is primary; ECDSA available for legacy verifiers. */
        PQC_PRIMARY,

        /** Classical contexts disabled.  Full post-quantum operation. */
        PQC_ONLY
    }

    public static MigrationPlan phase1() {
        return new MigrationPlan(Phase.CLASSICAL_ONLY, false);
    }

    public static MigrationPlan phase2() {
        return new MigrationPlan(Phase.HYBRID, true);
    }

    public static MigrationPlan phase3() {
        return new MigrationPlan(Phase.PQC_PRIMARY, true);
    }

    public static MigrationPlan phase4() {
        return new MigrationPlan(Phase.PQC_ONLY, false);
    }
}
