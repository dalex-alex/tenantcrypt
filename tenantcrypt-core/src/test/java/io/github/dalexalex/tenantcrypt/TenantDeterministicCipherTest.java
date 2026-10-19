package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TenantDeterministicCipherTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId GLOBEX = TenantId.of("globex");

    private final TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
    private final MasterKeyRing ring = TestKeys.masterRing();

    private final TenantDeterministicCipher cipher =
            TenantDeterministicCipher.builder().masterKeys(ring).keyProvider(provider).build();

    @ParameterizedTest
    @ValueSource(strings = {"", "x", "alice@example.com", "ünïcødé — 中文 🔐"})
    @DisplayName("round-trips, so the searchable column is also readable")
    void roundTrip(String plaintext) {
        assertThat(cipher.decrypt(ACME, cipher.encrypt(ACME, plaintext))).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("deterministic — the same input always gives the same stored value")
    void deterministic() {
        String first = cipher.encrypt(ACME, "alice@example.com");
        for (int i = 0; i < 20; i++) {
            assertThat(cipher.encrypt(ACME, "alice@example.com")).isEqualTo(first);
        }
    }

    @Test
    @DisplayName("this is exactly what randomised encryption cannot do")
    void contrastWithRandomisedEncryption() {
        TenantCipher randomised =
                TenantCipher.builder().masterKeys(ring).keyProvider(provider).build();

        Set<String> randomisedValues = new HashSet<>();
        Set<String> deterministicValues = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            randomisedValues.add(randomised.encrypt(ACME, "same input"));
            deterministicValues.add(cipher.encrypt(ACME, "same input"));
        }

        assertThat(randomisedValues).as("randomised: never comparable").hasSize(10);
        assertThat(deterministicValues).as("deterministic: always comparable").hasSize(1);
    }

    @Test
    @DisplayName("distinct inputs give distinct values")
    void distinguishesInputs() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            seen.add(cipher.encrypt(ACME, "user" + i + "@example.com"));
        }
        assertThat(seen).hasSize(100);
    }

    @Test
    @DisplayName("tenant-scoped: the same value under two tenants is not comparable")
    void tenantScoped() {
        assertThat(cipher.encrypt(ACME, "alice@example.com"))
                .isNotEqualTo(cipher.encrypt(GLOBEX, "alice@example.com"));
    }

    @Test
    @DisplayName("the envelope is version 0x02, distinguishing it from randomised ciphertext")
    void versionByte() {
        byte[] envelope = cipher.encryptBytes(ACME, "value".getBytes(StandardCharsets.UTF_8));

        assertThat(envelope[0]).isEqualTo((byte) 0x02);
        assertThat(cipher.keyIdOf(envelope)).isEqualTo("m1:t1");
        // header(2 + 5) + siv tag(16) + ciphertext(5)
        assertThat(envelope).hasSize(2 + 5 + 16 + 5);
    }

    @Test
    @DisplayName("the two ciphers refuse each other's values by name, not by tag failure")
    void formatsDoNotMix() {
        TenantCipher randomised =
                TenantCipher.builder().masterKeys(ring).keyProvider(provider).build();

        byte[] deterministicValue = cipher.encryptBytes(ACME, "v".getBytes());
        byte[] randomisedValue = randomised.encryptBytes(ACME, "v".getBytes());

        assertThatExceptionOfType(MalformedEnvelopeException.class)
                .isThrownBy(() -> randomised.decryptBytes(ACME, deterministicValue))
                .withMessageContaining("TenantDeterministicCipher");

        assertThatExceptionOfType(MalformedEnvelopeException.class)
                .isThrownBy(() -> cipher.decryptBytes(ACME, randomisedValue))
                .withMessageContaining("TenantCipher");
    }

    @Test
    @DisplayName("a value cannot be decrypted by another tenant")
    void crossTenantDecryptionFails() {
        byte[] envelope = cipher.encryptBytes(ACME, "acme value".getBytes());

        assertThatExceptionOfType(DecryptionFailedException.class)
                .isThrownBy(() -> cipher.decryptBytes(GLOBEX, envelope));
    }

    @Test
    @DisplayName("tamper detection: a flipped bit anywhere fails")
    void tamperDetection() {
        byte[] baseline = cipher.encryptBytes(ACME, "a value worth protecting".getBytes());

        for (int index : new int[] {0, 1, 3, 2 + 5, baseline.length - 1}) {
            byte[] tampered = baseline.clone();
            tampered[index] ^= 0x01;
            assertThatExceptionOfType(TenantCryptoException.class)
                    .as("a flipped bit at offset %d must fail", index)
                    .isThrownBy(() -> cipher.decryptBytes(ACME, tampered));
        }
    }

    @Test
    @DisplayName("the stored value records its key id, so stale rows are findable after rotation")
    void rotationIsDetectable() {
        String stored = cipher.encrypt(ACME, "alice@example.com");
        assertThat(cipher.needsRotation(ACME, stored)).isFalse();

        provider.add("t2").current("t2");

        assertThat(cipher.needsRotation(ACME, stored))
                .as("this is the property a fingerprint cannot have")
                .isTrue();
        assertThat(cipher.keyIdOf(stored)).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("rewrap moves a value to the current key and it stays comparable")
    void rewrap() {
        String stored = cipher.encrypt(ACME, "alice@example.com");
        provider.add("t2").current("t2");

        String rewrapped = cipher.rewrapString(ACME, stored);

        assertThat(cipher.keyIdOf(rewrapped)).isEqualTo("m1:t2");
        assertThat(cipher.decrypt(ACME, rewrapped)).isEqualTo("alice@example.com");
        assertThat(cipher.needsRotation(ACME, rewrapped)).isFalse();
        // Still usable as a lookup value under the new key.
        assertThat(cipher.encrypt(ACME, "alice@example.com")).isEqualTo(rewrapped);
    }

    @Test
    @DisplayName("during a transition, a lookup can be run against both generations")
    void queryBothGenerationsDuringTransition() {
        String underOldKey = cipher.encrypt(ACME, "alice@example.com");
        provider.add("t2").current("t2");
        String underNewKey = cipher.encrypt(ACME, "alice@example.com");

        assertThat(underOldKey).isNotEqualTo(underNewKey);
        // Both are valid lookup values; a transitional query uses IN (old, new).
        assertThat(cipher.decrypt(ACME, underOldKey)).isEqualTo("alice@example.com");
        assertThat(cipher.decrypt(ACME, underNewKey)).isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("isolation holds even if the provider shares key material across tenants")
    void isolationDoesNotDependOnTheProvider() {
        TenantKeyProvider shared = TestKeys.sharedKeyProvider();
        TenantDeterministicCipher sloppy =
                TenantDeterministicCipher.builder().masterKeys(ring).keyProvider(shared).build();

        assertThat(sloppy.encrypt(ACME, "alice@example.com"))
                .isNotEqualTo(sloppy.encrypt(GLOBEX, "alice@example.com"));
    }

    @Test
    @DisplayName("the deterministic key is unrelated to the field and fingerprint keys")
    void keyUseSeparation() {
        TenantCipher randomised =
                TenantCipher.builder().masterKeys(ring).keyProvider(provider).build();
        TenantFingerprint fingerprints =
                TenantFingerprint.builder().masterKeys(ring).keyProvider(provider).build();

        String deterministic = cipher.encrypt(ACME, "value");
        String fingerprint = fingerprints.of(ACME, "value");

        assertThat(deterministic).isNotEqualTo(fingerprint);
        assertThat(randomised.encrypt(ACME, "value")).isNotEqualTo(deterministic);
    }

    @Test
    @DisplayName("caching does not change the answer")
    void caching() {
        String first = cipher.encrypt(ACME, "alice@example.com");
        cipher.clearCache();
        assertThat(cipher.encrypt(ACME, "alice@example.com")).isEqualTo(first);
    }
}
