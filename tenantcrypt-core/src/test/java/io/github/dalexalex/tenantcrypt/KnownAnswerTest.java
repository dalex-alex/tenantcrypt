package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Frozen vectors. These values were produced by this library and are checked in verbatim, so any
 * change to the envelope layout, the associated-data composition, the HKDF derivation, the purpose
 * labels or the reference provider's key derivation fails here.
 *
 * <p>That matters more than it looks: all of those are silent. A change to any of them still
 * encrypts and still decrypts within one process — it simply stops being able to read data the
 * previous release wrote. This test is the tripwire for that class of mistake.
 *
 * <p>If one of these assertions fails, the format changed. That is a deliberate decision requiring
 * a new version byte and a migration path, not a test to update.
 */
class KnownAnswerTest {

    private static final TenantId TENANT_A = TenantId.of("tenant-a");
    private static final TenantId TENANT_B = TenantId.of("tenant-b");

    private static final String PLAINTEXT = "known answer plaintext";

    /** Produced by this library under the fixtures below, and checked in verbatim. */
    private static final String CIPHERTEXT =
            "AQVtMTp0MdKsg03Gb0+U3/8QVjzzAOy3nRq+/1332EX7VXU3id30NBZtyYu8nprjV6P6ZvrtFl+8";

    private static final String TENANT_KEY_BASE64 = "Cpc59dUNsGhY4loA924qmFXIryPK24nA70j3k4tRBfw=";

    private static final String FINGERPRINT_EMPTY =
            "m1:t1:35522e3f58bd2bcd0ee76c37840e62a74f14be246914f8a9830fce5c52b72f2c";
    private static final String FINGERPRINT_ABC =
            "m1:t1:13623a4dada1d20f52b2888e78c5543e2a53c0fbce5982f934efc765ff2abd13";
    private static final String FINGERPRINT_ABC_TENANT_B =
            "m1:t1:806e6575aef2ff96025928a74776c92e941672e393deeb98e7735337e5ea7566";

    private final MasterKeyRing ring = MasterKeyRing.of("m1", TestKeys.bytes32("kat-master"));
    private final SeedDerivedKeyProvider provider =
            SeedDerivedKeyProvider.of("kat-seed-0123456789abcdefghijklmnop", "t1");

    private final TenantCipher cipher =
            TenantCipher.builder().masterKeys(ring).keyProvider(provider).build();
    private final TenantFingerprint fingerprints =
            TenantFingerprint.builder().masterKeys(ring).keyProvider(provider).build();

    @Test
    @DisplayName("a ciphertext frozen at an earlier release still decrypts")
    void ciphertextStillDecrypts() {
        assertThat(cipher.decrypt(TENANT_A, CIPHERTEXT)).isEqualTo(PLAINTEXT);
    }

    @Test
    @DisplayName("the frozen ciphertext names the expected key id")
    void keyId() {
        assertThat(cipher.keyIdOf(CIPHERTEXT)).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("the envelope header is version 0x01, a 5-byte key id, then 'm1:t1'")
    void headerLayout() {
        byte[] envelope = Base64.getDecoder().decode(CIPHERTEXT);

        assertThat(envelope[0]).isEqualTo((byte) 0x01);
        assertThat(envelope[1]).isEqualTo((byte) 5);
        assertThat(new String(envelope, 2, 5, java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("the reference provider derives the frozen tenant key")
    void tenantKeyDerivation() {
        assertThat(Base64.getEncoder().encodeToString(provider.current(TENANT_A).material()))
                .isEqualTo(TENANT_KEY_BASE64);
    }

    @Test
    @DisplayName("a fingerprint records the key generation that produced it")
    void fingerprintRecordsItsGeneration() {
        assertThat(fingerprints.keyIdOf(fingerprints.of(TENANT_A, "abc"))).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("fingerprints match their frozen values")
    void fingerprintVectors() {
        assertThat(fingerprints.of(TENANT_A, new byte[0])).isEqualTo(FINGERPRINT_EMPTY);
        assertThat(fingerprints.of(TENANT_A, "abc")).isEqualTo(FINGERPRINT_ABC);
    }

    @Test
    @DisplayName("the same content under another tenant has a different frozen fingerprint")
    void fingerprintTenantScoping() {
        assertThat(fingerprints.of(TENANT_B, "abc")).isEqualTo(FINGERPRINT_ABC_TENANT_B);
        assertThat(FINGERPRINT_ABC).isNotEqualTo(FINGERPRINT_ABC_TENANT_B);
    }

    @Test
    @DisplayName("the purpose labels are part of the format and must not drift")
    void purposeLabels() {
        assertThat(Purpose.FIELD.label()).isEqualTo("tenantcrypt-field-v1");
        assertThat(Purpose.FINGERPRINT.label()).isEqualTo("tenantcrypt-fingerprint-v1");
    }

    @Test
    @DisplayName("the tenant id is part of the derivation, so the same key material differs per tenant")
    void tenantIsBoundIntoDerivation() {
        // Both tenants resolve the same key id from the same seed provider, so only the derivation's
        // tenant binding distinguishes these. If that binding were removed, they would be equal.
        assertThat(fingerprints.of(TENANT_A, "abc")).isNotEqualTo(fingerprints.of(TENANT_B, "abc"));
    }
}
