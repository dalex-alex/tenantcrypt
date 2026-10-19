package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TenantCipherTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId OTHER = TenantId.of("globex");

    private final TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
    private final TenantCipher cipher =
            TenantCipher.builder().masterKeys(TestKeys.masterRing()).keyProvider(provider).build();

    @Nested
    @DisplayName("round trips")
    class RoundTrips {

        @ParameterizedTest
        @ValueSource(strings = {"", "x", "hello world", "ünïcødé — em dash, ß, 中文, 🔐"})
        void strings(String plaintext) {
            assertThat(cipher.decrypt(ACME, cipher.encrypt(ACME, plaintext))).isEqualTo(plaintext);
        }

        @Test
        void emptyByteArray() {
            assertThat(cipher.decryptBytes(ACME, cipher.encryptBytes(ACME, new byte[0]))).isEmpty();
        }

        @Test
        void aMultiMegabytePayload() {
            byte[] big = new byte[3 * 1024 * 1024];
            for (int i = 0; i < big.length; i++) {
                big[i] = (byte) i;
            }
            assertThat(cipher.decryptBytes(ACME, cipher.encryptBytes(ACME, big))).isEqualTo(big);
        }

        @Test
        void allByteValuesSurvive() {
            byte[] every = new byte[256];
            for (int i = 0; i < 256; i++) {
                every[i] = (byte) i;
            }
            assertThat(cipher.decryptBytes(ACME, cipher.encryptBytes(ACME, every))).isEqualTo(every);
        }
    }

    @Test
    @DisplayName("encryption is randomised, so ciphertext cannot be compared for equality")
    void encryptionIsRandomised() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            seen.add(cipher.encrypt(ACME, "same input"));
        }
        assertThat(seen).hasSize(50);
    }

    @Test
    @DisplayName("the envelope carries version 0x01 and the composed key id")
    void envelopeLayout() {
        byte[] envelope = cipher.encryptBytes(ACME, "payload".getBytes(StandardCharsets.UTF_8));

        assertThat(envelope[0]).isEqualTo((byte) 0x01);
        assertThat(envelope[1]).isEqualTo((byte) "m1:t1".length());
        assertThat(new String(envelope, 2, 5, StandardCharsets.UTF_8)).isEqualTo("m1:t1");
        assertThat(cipher.keyIdOf(envelope)).isEqualTo("m1:t1");

        // header(2 + 5) + iv(12) + ciphertext(7) + tag(16)
        assertThat(envelope).hasSize(2 + 5 + 12 + 7 + 16);
    }

    @Nested
    @DisplayName("tamper detection")
    class Tampering {

        @Test
        void aFlippedCiphertextBitFails() {
            assertTamperingFails(2 + 5 + 12, "ciphertext");
        }

        @Test
        void aFlippedIvBitFails() {
            assertTamperingFails(2 + 5, "iv");
        }

        @Test
        void aFlippedTagBitFails() {
            byte[] envelope = cipher.encryptBytes(ACME, "payload".getBytes(StandardCharsets.UTF_8));
            assertTamperingFails(envelope.length - 1, "tag");
        }

        @Test
        @DisplayName("editing the key id in the header is caught, because the header is bound as AAD")
        void aTamperedHeaderFails() {
            byte[] envelope = cipher.encryptBytes(ACME, "payload".getBytes(StandardCharsets.UTF_8));
            // Rewrite the key id "m1:t1" to "m1:t2" without touching the ciphertext.
            envelope[2 + 4] = (byte) '2';

            // The provider does know a t2 key, so this reaches the AEAD and fails on the tag
            // rather than failing to resolve a key.
            provider.add("t2");
            assertThatExceptionOfType(DecryptionFailedException.class)
                    .isThrownBy(() -> cipher.decryptBytes(ACME, envelope));
        }

        private void assertTamperingFails(int index, String what) {
            byte[] envelope = cipher.encryptBytes(ACME, "payload".getBytes(StandardCharsets.UTF_8));
            envelope[index] ^= 0x01;
            assertThatExceptionOfType(DecryptionFailedException.class)
                    .as("a flipped bit in the %s must fail", what)
                    .isThrownBy(() -> cipher.decryptBytes(ACME, envelope));
        }
    }

    @Test
    @DisplayName("a value cannot be decrypted by another tenant, because the tenant id is bound as AAD")
    void crossTenantIsolation() {
        byte[] envelope = cipher.encryptBytes(ACME, "acme's secret".getBytes(StandardCharsets.UTF_8));

        assertThatExceptionOfType(DecryptionFailedException.class)
                .isThrownBy(() -> cipher.decryptBytes(OTHER, envelope));
    }

    @Test
    @DisplayName("relocating a ciphertext to another tenant fails even when both use the same key id")
    void tenantBindingIsNotJustKeyIsolation() {
        // Both tenants resolve key id "t1"; only the AAD distinguishes them.
        assertThat(cipher.keyIdOf(cipher.encryptBytes(ACME, new byte[] {1})))
                .isEqualTo(cipher.keyIdOf(cipher.encryptBytes(OTHER, new byte[] {1})));

        byte[] acmeValue = cipher.encryptBytes(ACME, "secret".getBytes(StandardCharsets.UTF_8));
        assertThatExceptionOfType(DecryptionFailedException.class)
                .isThrownBy(() -> cipher.decryptBytes(OTHER, acmeValue));
    }

    @Nested
    @DisplayName("malformed input is rejected, not guessed at")
    class Malformed {

        @Test
        void tooShortForAHeader() {
            assertMalformed(new byte[] {0x01});
        }

        @Test
        @DisplayName("the legacy header-less layout is rejected rather than silently misread")
        void legacyLayoutIsRejected() {
            // iv(12) || ciphertext || tag(16) with no header — the format this library replaced.
            byte[] legacy = new byte[12 + 8 + 16];
            legacy[0] = 0x2a;
            assertMalformed(legacy);
        }

        @Test
        @DisplayName("a legacy value whose first byte happens to be 0x01 is still rejected")
        void legacyValueThatLooksLikeAVersionByte() {
            byte[] legacy = new byte[12 + 8 + 16];
            legacy[0] = 0x01;
            // Second byte is an IV byte, read as a key-id length; whatever it is, the value does
            // not authenticate, and no fallback path exists to misread it under.
            legacy[1] = 0x05;
            assertThatExceptionOfType(TenantCryptoException.class)
                    .isThrownBy(() -> cipher.decryptBytes(ACME, legacy));
        }

        @Test
        void anUnsupportedVersionByte() {
            byte[] envelope = cipher.encryptBytes(ACME, new byte[] {1});
            envelope[0] = 0x02;
            assertMalformed(envelope);
        }

        @Test
        void anEmptyKeyIdLength() {
            byte[] envelope = cipher.encryptBytes(ACME, new byte[] {1});
            envelope[1] = 0x00;
            assertMalformed(envelope);
        }

        @Test
        void aKeyIdLengthThatOverrunsTheBuffer() {
            byte[] envelope = cipher.encryptBytes(ACME, new byte[] {1});
            envelope[1] = (byte) 0xFF;
            assertMalformed(envelope);
        }

        @Test
        void notBase64() {
            assertThatExceptionOfType(MalformedEnvelopeException.class)
                    .isThrownBy(() -> cipher.decrypt(ACME, "not base64 !!!"));
        }

        @Test
        void base64OfSomethingTooShort() {
            String encoded = Base64.getEncoder().encodeToString(new byte[] {0x01});
            assertThatExceptionOfType(MalformedEnvelopeException.class)
                    .isThrownBy(() -> cipher.decrypt(ACME, encoded));
        }

        private void assertMalformed(byte[] envelope) {
            assertThatExceptionOfType(MalformedEnvelopeException.class)
                    .isThrownBy(() -> cipher.decryptBytes(ACME, envelope));
        }
    }

    @Test
    @DisplayName("an unresolvable key id is reported as such, not as a decryption failure")
    void unknownKeyId() {
        byte[] envelope = cipher.encryptBytes(ACME, new byte[] {1});
        TenantCipher withForgetfulProvider =
                TenantCipher.builder()
                        .masterKeys(TestKeys.masterRing())
                        .keyProvider(new TestKeys.FixedProvider("t9"))
                        .build();

        assertThatExceptionOfType(UnknownKeyException.class)
                .isThrownBy(() -> withForgetfulProvider.decryptBytes(ACME, envelope))
                .withMessageContaining("t1");
    }

    @Test
    @DisplayName("a retired master key version is reported as unknown")
    void unknownMasterKeyVersion() {
        byte[] envelope = cipher.encryptBytes(ACME, new byte[] {1});
        TenantCipher rotatedAway =
                TenantCipher.builder()
                        .masterKeys(MasterKeyRing.of("m2", TestKeys.bytes32("master-2")))
                        .keyProvider(provider)
                        .build();

        assertThatExceptionOfType(UnknownKeyException.class)
                .isThrownBy(() -> rotatedAway.decryptBytes(ACME, envelope))
                .withMessageContaining("m1");
    }

    @Test
    @DisplayName("the derived-key cache does not change results and can be cleared")
    void caching() {
        String encrypted = cipher.encrypt(ACME, "payload");
        assertThat(cipher.decrypt(ACME, encrypted)).isEqualTo("payload");

        cipher.clearCache();
        assertThatNoException().isThrownBy(() -> cipher.decrypt(ACME, encrypted));
        assertThat(cipher.decrypt(ACME, encrypted)).isEqualTo("payload");
    }

    @Test
    @DisplayName("a cipher whose cache holds one entry still serves many tenants correctly")
    void cacheEvictionIsTransparent() {
        TenantCipher tiny =
                TenantCipher.builder()
                        .masterKeys(TestKeys.masterRing())
                        .keyProvider(provider)
                        .cacheEntries(1)
                        .build();

        String acme = tiny.encrypt(ACME, "a");
        String other = tiny.encrypt(OTHER, "b");

        assertThat(tiny.decrypt(ACME, acme)).isEqualTo("a");
        assertThat(tiny.decrypt(OTHER, other)).isEqualTo("b");
        assertThat(tiny.decrypt(ACME, acme)).isEqualTo("a");
    }
}
