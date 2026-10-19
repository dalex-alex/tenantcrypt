package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TenantFingerprintTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId OTHER = TenantId.of("globex");

    private final TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
    private final TenantFingerprint fingerprints =
            TenantFingerprint.builder()
                    .masterKeys(TestKeys.masterRing())
                    .keyProvider(provider)
                    .build();

    @Test
    @DisplayName("the key generation, then 64 lowercase hex characters")
    void shape() {
        assertThat(fingerprints.of(ACME, "content")).matches("m1:t1:[0-9a-f]{64}");
    }

    @Test
    @DisplayName("the recorded generation is readable back off a stored value")
    void keyIdIsRecorded() {
        assertThat(fingerprints.keyIdOf(fingerprints.of(ACME, "content"))).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("a stale fingerprint is detectable after rotation — the whole reason for the prefix")
    void staleFingerprintsAreDetectable() {
        String stored = fingerprints.of(ACME, "content");
        assertThat(fingerprints.needsRotation(ACME, stored)).isFalse();

        provider.add("t2").current("t2");

        assertThat(fingerprints.needsRotation(ACME, stored)).isTrue();
        assertThat(fingerprints.keyIdOf(stored)).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("recomputing from the plaintext under the new key restores the lookup")
    void recomputeRestoresLookups() {
        String stored = fingerprints.of(ACME, "a document");
        provider.add("t2").current("t2");
        fingerprints.clearCache();

        // The input was plaintext all along, so a recompute pass simply re-MACs it.
        String recomputed = fingerprints.of(ACME, "a document");

        assertThat(recomputed).isNotEqualTo(stored);
        assertThat(fingerprints.needsRotation(ACME, recomputed)).isFalse();
        assertThat(fingerprints.of(ACME, "a document")).isEqualTo(recomputed);
    }

    @Test
    @DisplayName("under() reproduces a retired generation, so a transition can query both")
    void underNamedGeneration() {
        String stored = fingerprints.of(ACME, "a document");
        provider.add("t2").current("t2");
        fingerprints.clearCache();

        assertThat(fingerprints.under(ACME, "m1:t1", "a document")).isEqualTo(stored);
        assertThat(fingerprints.under(ACME, "m1:t2", "a document"))
                .isEqualTo(fingerprints.of(ACME, "a document"));
    }

    @Test
    @DisplayName("a retired generation the provider has forgotten is reported, not guessed")
    void underUnknownGeneration() {
        assertThatExceptionOfType(UnknownKeyException.class)
                .isThrownBy(() -> fingerprints.under(ACME, "m1:t9", "content"));
    }

    @Test
    @DisplayName("something that is not a fingerprint is rejected rather than parsed")
    void malformedFingerprint() {
        assertThatExceptionOfType(MalformedEnvelopeException.class)
                .isThrownBy(() -> fingerprints.keyIdOf("not-a-fingerprint"));
        assertThatExceptionOfType(MalformedEnvelopeException.class)
                .isThrownBy(() -> fingerprints.keyIdOf("13623a4dada1d20f52b2888e78c5543e"));
    }

    @Test
    @DisplayName("deterministic — this is the whole point, and what ciphertext cannot do")
    void deterministic() {
        String first = fingerprints.of(ACME, "the same document");
        for (int i = 0; i < 20; i++) {
            assertThat(fingerprints.of(ACME, "the same document")).isEqualTo(first);
        }
    }

    @Test
    @DisplayName("different content gives different fingerprints")
    void distinguishesContent() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            seen.add(fingerprints.of(ACME, "document " + i));
        }
        assertThat(seen).hasSize(100);
    }

    /**
     * Note this passes with a per-tenant provider even if the library delegated isolation entirely
     * to the provider. {@link TenantIsolationTest} is the test that actually pins the property.
     */
    @Test
    @DisplayName("tenant-scoped — the same content gives different fingerprints per tenant")
    void tenantScoped() {
        assertThat(fingerprints.of(ACME, "identical content"))
                .isNotEqualTo(fingerprints.of(OTHER, "identical content"));
    }

    @Test
    @DisplayName("the string and byte overloads agree for UTF-8 content")
    void overloadsAgree() {
        String text = "ünïcødé — 中文 🔐";
        assertThat(fingerprints.of(ACME, text))
                .isEqualTo(fingerprints.of(ACME, text.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("an empty input still fingerprints")
    void emptyInput() {
        assertThat(fingerprints.of(ACME, new byte[0])).matches("m1:t1:[0-9a-f]{64}");
    }

    @Test
    @DisplayName("keyed, not a bare digest: the value is not SHA-256 of the content")
    void keyedNotPlainDigest() throws Exception {
        byte[] content = "a document".getBytes(StandardCharsets.UTF_8);
        String sha256 =
                java.util.HexFormat.of()
                        .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(content));

        assertThat(fingerprints.of(ACME, content)).isNotEqualTo(sha256);
    }

    @Test
    @DisplayName("the fingerprint changes when the master key changes, which invalidates every stored one")
    void masterKeyRotationInvalidatesFingerprints() {
        TenantFingerprint afterRotation =
                TenantFingerprint.builder()
                        .masterKeys(MasterKeyRing.of("m2", TestKeys.bytes32("master-2")))
                        .keyProvider(provider)
                        .build();

        assertThat(afterRotation.of(ACME, "content")).isNotEqualTo(fingerprints.of(ACME, "content"));
    }

    @Test
    @DisplayName("the fingerprint changes when the tenant key changes")
    void tenantKeyRotationInvalidatesFingerprints() {
        String before = fingerprints.of(ACME, "content");
        provider.add("t2").current("t2");
        fingerprints.clearCache();

        assertThat(fingerprints.of(ACME, "content")).isNotEqualTo(before);
    }

    @Test
    @DisplayName("a missing current key is reported, not silently fingerprinted under nothing")
    void missingKey() {
        TenantFingerprint broken =
                TenantFingerprint.builder()
                        .masterKeys(TestKeys.masterRing())
                        .keyProvider(
                                new TenantKeyProvider() {
                                    @Override
                                    public TenantKey current(TenantId tenant) {
                                        return null;
                                    }

                                    @Override
                                    public TenantKey resolve(TenantId tenant, String keyId) {
                                        return null;
                                    }
                                })
                        .build();

        assertThatExceptionOfType(UnknownKeyException.class)
                .isThrownBy(() -> broken.of(ACME, "content"));
    }

    @Test
    @DisplayName("caching does not change the answer")
    void caching() {
        String first = fingerprints.of(ACME, "content");
        fingerprints.clearCache();
        assertThat(fingerprints.of(ACME, "content")).isEqualTo(first);
    }
}
