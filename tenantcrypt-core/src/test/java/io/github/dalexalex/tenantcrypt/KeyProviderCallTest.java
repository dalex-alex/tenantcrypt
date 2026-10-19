package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A key provider is backed by a secret store in production, so resolving a key is a network call.
 * The derived-primitive cache exists to make that cost amortised — which only works if the cache is
 * consulted <em>before</em> the provider, not after.
 *
 * <p>These tests count provider calls to pin that ordering, because getting it wrong is invisible:
 * everything still works, just with a round-trip per operation.
 */
class KeyProviderCallTest {

    private static final TenantId ACME = TenantId.of("acme");

    private final AtomicInteger currentCalls = new AtomicInteger();
    private final AtomicInteger resolveCalls = new AtomicInteger();

    private final TenantKeyProvider counting =
            new TenantKeyProvider() {
                private final TestKeys.FixedProvider delegate = new TestKeys.FixedProvider("t1");

                @Override
                public TenantKey current(TenantId tenant) {
                    currentCalls.incrementAndGet();
                    return delegate.current(tenant);
                }

                @Override
                public TenantKey resolve(TenantId tenant, String keyId) {
                    resolveCalls.incrementAndGet();
                    return delegate.resolve(tenant, keyId);
                }
            };

    private final MasterKeyRing ring = TestKeys.masterRing();

    @Test
    @DisplayName("repeated decrypts consult the provider once, not once per call")
    void decryptHitsTheCache() {
        TenantCipher cipher =
                TenantCipher.builder().masterKeys(ring).keyProvider(counting).build();
        String stored = cipher.encrypt(ACME, "payload");
        resolveCalls.set(0);

        for (int i = 0; i < 25; i++) {
            assertThat(cipher.decrypt(ACME, stored)).isEqualTo("payload");
        }

        assertThat(resolveCalls.get())
                .as("the key id comes from the envelope, so a warm cache needs no provider call")
                .isZero();
    }

    @Test
    @DisplayName("repeated deterministic decrypts also stay off the provider")
    void deterministicDecryptHitsTheCache() {
        TenantDeterministicCipher cipher =
                TenantDeterministicCipher.builder().masterKeys(ring).keyProvider(counting).build();
        String stored = cipher.encrypt(ACME, "alice@example.com");
        resolveCalls.set(0);

        for (int i = 0; i < 25; i++) {
            assertThat(cipher.decrypt(ACME, stored)).isEqualTo("alice@example.com");
        }

        assertThat(resolveCalls.get()).isZero();
    }

    @Test
    @DisplayName("fingerprinting a named generation repeatedly consults the provider once")
    void fingerprintUnderHitsTheCache() {
        TenantFingerprint fingerprints =
                TenantFingerprint.builder().masterKeys(ring).keyProvider(counting).build();
        fingerprints.under(ACME, "m1:t1", "content");
        resolveCalls.set(0);

        for (int i = 0; i < 25; i++) {
            fingerprints.under(ACME, "m1:t1", "content");
        }

        assertThat(resolveCalls.get()).isZero();
    }

    @Test
    @DisplayName("encrypting still asks for the current key, because the key id is not known yet")
    void encryptMustAskForTheCurrentKey() {
        TenantCipher cipher =
                TenantCipher.builder().masterKeys(ring).keyProvider(counting).build();
        currentCalls.set(0);

        cipher.encrypt(ACME, "payload");

        assertThat(currentCalls.get())
                .as("unavoidable: the current key id is part of the cache key")
                .isPositive();
    }

    @Test
    @DisplayName("a cache miss does resolve, so the deferral has not simply dropped the call")
    void cacheMissStillResolves() {
        TenantCipher cipher =
                TenantCipher.builder().masterKeys(ring).keyProvider(counting).build();
        String stored = cipher.encrypt(ACME, "payload");
        cipher.clearCache();
        resolveCalls.set(0);

        assertThat(cipher.decrypt(ACME, stored)).isEqualTo("payload");

        assertThat(resolveCalls.get()).isEqualTo(1);
    }
}
