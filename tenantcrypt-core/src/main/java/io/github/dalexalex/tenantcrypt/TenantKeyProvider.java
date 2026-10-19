package io.github.dalexalex.tenantcrypt;

/**
 * Supplies per-tenant data keys. This is the one extension point that matters, and in production it
 * is yours to write — it is where a secret store (Vault, OpenBao, AWS Secrets Manager, a KMS)
 * plugs in.
 *
 * <p>Two methods, because rotation needs both directions: {@link #current} says what to encrypt new
 * data under, and {@link #resolve} answers for a key id read out of an existing ciphertext. A
 * provider that only implements the first cannot decrypt its own history.
 *
 * <p>Implementations are called on every encrypt and decrypt, so they should cache. They must be
 * thread-safe.
 *
 * <p><strong>A wrong key does not fail loudly — it writes ciphertext nobody can read back.</strong>
 * Test a provider against the properties in the shipped test suite before trusting it with data.
 */
public interface TenantKeyProvider {

    /** The key new data for this tenant should be encrypted under. */
    TenantKey current(TenantId tenant);

    /**
     * The key a stored ciphertext names.
     *
     * @throws UnknownKeyException if this provider cannot supply that key; never return a
     *     different key, and never return null
     */
    TenantKey resolve(TenantId tenant, String keyId);
}
