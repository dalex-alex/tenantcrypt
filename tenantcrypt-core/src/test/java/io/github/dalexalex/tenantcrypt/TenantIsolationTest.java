package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Cross-tenant isolation must be a property of this library, not a promise the key provider is
 * trusted to keep.
 *
 * <p>Every test here runs against a deliberately broken provider that hands the same key material
 * to every tenant. That is a plausible mistake — a misconfigured secret-store path, a cache keyed
 * on the wrong thing, a stub left in place — and it is the kind of mistake that is invisible in
 * testing, because everything still encrypts and decrypts happily within one tenant.
 *
 * <p>The other isolation tests in this suite use a per-tenant provider, so they would pass even if
 * the library delegated isolation entirely to the provider. These would not.
 */
class TenantIsolationTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId GLOBEX = TenantId.of("globex");

    private static final TenantKeyProvider SHARED_KEY_PROVIDER = TestKeys.sharedKeyProvider();

    private final MasterKeyRing ring = TestKeys.masterRing();

    private final TenantCipher cipher =
            TenantCipher.builder().masterKeys(ring).keyProvider(SHARED_KEY_PROVIDER).build();
    private final TenantFingerprint fingerprints =
            TenantFingerprint.builder().masterKeys(ring).keyProvider(SHARED_KEY_PROVIDER).build();

    @Test
    @DisplayName("fingerprints differ across tenants even when the provider shares key material")
    void fingerprintsAreScopedByDerivation() {
        String acme = fingerprints.of(ACME, "identical content");
        String globex = fingerprints.of(GLOBEX, "identical content");

        assertThat(acme)
                .as("the tenant id is mixed into the key derivation, so this cannot collide")
                .isNotEqualTo(globex);
    }

    @Test
    @DisplayName("one tenant cannot confirm another holds a document, which is the point of keying")
    void noCrossTenantConfirmation() {
        // Acme stores a fingerprint. Globex, holding the same content and the same underlying key
        // material, must not be able to reproduce Acme's stored value.
        String stored = fingerprints.of(ACME, "a shared document");

        assertThat(fingerprints.of(GLOBEX, "a shared document")).isNotEqualTo(stored);
    }

    @Test
    @DisplayName("ciphertext does not decrypt under another tenant when key material is shared")
    void ciphertextIsScoped() {
        byte[] envelope = cipher.encryptBytes(ACME, "acme's secret".getBytes());

        assertThatExceptionOfType(DecryptionFailedException.class)
                .isThrownBy(() -> cipher.decryptBytes(GLOBEX, envelope));
    }

    @Test
    @DisplayName("each tenant still round-trips its own data")
    void eachTenantStillWorks() {
        String acme = cipher.encrypt(ACME, "acme value");
        String globex = cipher.encrypt(GLOBEX, "globex value");

        assertThat(cipher.decrypt(ACME, acme)).isEqualTo("acme value");
        assertThat(cipher.decrypt(GLOBEX, globex)).isEqualTo("globex value");
    }

    @Test
    @DisplayName("fingerprints stay deterministic per tenant")
    void stillDeterministic() {
        assertThat(fingerprints.of(ACME, "content")).isEqualTo(fingerprints.of(ACME, "content"));
    }
}
