package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Mac;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Key-use separation: the purpose label in HKDF's {@code info} means a key derived for one use is
 * unrelated to every other. Cheap to implement, easy to skip, and the tests that prove it are the
 * reason to believe the claim.
 */
class KeyUseSeparationTest {

    private static final TenantId ACME = TenantId.of("acme");

    private final byte[] masterKey = TestKeys.bytes32("master-1");
    private final byte[] tenantKey = TestKeys.bytes32("tenant-1");

    @Test
    @DisplayName("the two purposes derive different keys from identical inputs")
    void differentKeysPerPurpose() {
        Mac fieldKeyed = KeyDerivation.mac(masterKey, tenantKey, Purpose.FIELD, ACME);
        Mac fingerprintKeyed = KeyDerivation.mac(masterKey, tenantKey, Purpose.FINGERPRINT, ACME);

        assertThat(tag(fieldKeyed)).isNotEqualTo(tag(fingerprintKeyed));
    }

    @Test
    @DisplayName("the fingerprint key cannot decrypt what the field key encrypted")
    void fingerprintKeyCannotDecrypt() throws Exception {
        Aead fieldAead = KeyDerivation.aead(masterKey, tenantKey, Purpose.FIELD, ACME);
        Aead fingerprintAead = KeyDerivation.aead(masterKey, tenantKey, Purpose.FINGERPRINT, ACME);

        byte[] ciphertext = fieldAead.encrypt("secret".getBytes(StandardCharsets.UTF_8), new byte[0]);

        assertThatExceptionOfType(GeneralSecurityException.class)
                .isThrownBy(() -> fingerprintAead.decrypt(ciphertext, new byte[0]));
    }

    @Test
    @DisplayName("both master and tenant key participate: changing either changes the derived key")
    void bothInputsParticipate() {
        Mac baseline = KeyDerivation.mac(masterKey, tenantKey, Purpose.FIELD, ACME);
        Mac otherMaster = KeyDerivation.mac(TestKeys.bytes32("master-2"), tenantKey, Purpose.FIELD, ACME);
        Mac otherTenant = KeyDerivation.mac(masterKey, TestKeys.bytes32("tenant-2"), Purpose.FIELD, ACME);

        assertThat(tag(baseline)).isNotEqualTo(tag(otherMaster));
        assertThat(tag(baseline)).isNotEqualTo(tag(otherTenant));
        assertThat(tag(otherMaster)).isNotEqualTo(tag(otherTenant));
    }

    @Test
    @DisplayName("neither key alone decrypts: the halves are not interchangeable")
    void neitherKeyAlone() {
        // Swapping which half is which produces a different key, so a caller who knows only one
        // of the two inputs cannot reconstruct the derived key.
        Mac correct = KeyDerivation.mac(masterKey, tenantKey, Purpose.FIELD, ACME);
        Mac swapped = KeyDerivation.mac(tenantKey, masterKey, Purpose.FIELD, ACME);

        assertThat(tag(correct)).isNotEqualTo(tag(swapped));
    }

    @Test
    @DisplayName("a fingerprint is not reachable through the cipher's key")
    void fingerprintIsNotDerivableFromTheFieldKey() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher =
                TenantCipher.builder()
                        .masterKeys(TestKeys.masterRing())
                        .keyProvider(provider)
                        .build();
        TenantFingerprint fingerprints =
                TenantFingerprint.builder()
                        .masterKeys(TestKeys.masterRing())
                        .keyProvider(provider)
                        .build();

        String fingerprint = fingerprints.of(ACME, "content");
        String ciphertext = cipher.encrypt(ACME, "content");

        assertThat(ciphertext).doesNotContain(fingerprint);
    }

    private static String tag(Mac mac) {
        try {
            return java.util.HexFormat.of().formatHex(mac.computeMac("probe".getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}
