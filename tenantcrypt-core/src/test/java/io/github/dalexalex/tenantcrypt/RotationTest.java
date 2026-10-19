package io.github.dalexalex.tenantcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Rotation is what the versioned envelope buys. Without a header there is no way to tell which key
 * encrypted a row, so changing a key orphans every row already written under the old one and no
 * query finds them. These tests cover both halves of the key id rotating, independently.
 */
class RotationTest {

    private static final TenantId ACME = TenantId.of("acme");

    @Test
    @DisplayName("a value written under the old tenant key still reads after rotation")
    void oldValuesStillReadAfterTenantKeyRotation() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher = cipherFor(provider, TestKeys.masterRing());

        String written = cipher.encrypt(ACME, "written under t1");
        assertThat(cipher.keyIdOf(written)).isEqualTo("m1:t1");

        provider.add("t2").current("t2");

        assertThat(cipher.decrypt(ACME, written)).isEqualTo("written under t1");
        assertThat(cipher.encrypt(ACME, "new")).satisfies(v -> assertThat(cipher.keyIdOf(v)).isEqualTo("m1:t2"));
    }

    @Test
    @DisplayName("needsRotation identifies exactly the values not under the current key")
    void needsRotation() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher = cipherFor(provider, TestKeys.masterRing());

        String old = cipher.encrypt(ACME, "payload");
        assertThat(cipher.needsRotation(ACME, old)).isFalse();

        provider.add("t2").current("t2");
        assertThat(cipher.needsRotation(ACME, old)).isTrue();

        String fresh = cipher.encrypt(ACME, "payload");
        assertThat(cipher.needsRotation(ACME, fresh)).isFalse();
    }

    @Test
    @DisplayName("a master key rotation is detected too")
    void needsRotationOnMasterKeyChange() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        MasterKeyRing ring = TestKeys.masterRing();
        String old = cipherFor(provider, ring).encrypt(ACME, "payload");

        TenantCipher afterMasterRotation =
                cipherFor(provider, ring.with("m2", TestKeys.bytes32("master-2")));

        assertThat(afterMasterRotation.needsRotation(ACME, old)).isTrue();
    }

    @Test
    @DisplayName("rewrap preserves the plaintext and moves the value to the current key")
    void rewrap() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher = cipherFor(provider, TestKeys.masterRing());

        String old = cipher.encrypt(ACME, "the plaintext");
        provider.add("t2").current("t2");

        String rewrapped = cipher.rewrapString(ACME, old);

        assertThat(cipher.keyIdOf(rewrapped)).isEqualTo("m1:t2");
        assertThat(cipher.decrypt(ACME, rewrapped)).isEqualTo("the plaintext");
        assertThat(cipher.needsRotation(ACME, rewrapped)).isFalse();
    }

    @Test
    @DisplayName("rewrap works across a master key rotation, with both versions still in the ring")
    void rewrapAcrossMasterKeys() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        MasterKeyRing ring = TestKeys.masterRing();
        byte[] old = cipherFor(provider, ring).encryptBytes(ACME, "bytes".getBytes());

        TenantCipher rotated = cipherFor(provider, ring.with("m2", TestKeys.bytes32("master-2")));
        byte[] rewrapped = rotated.rewrap(ACME, old);

        assertThat(rotated.keyIdOf(rewrapped)).isEqualTo("m2:t1");
        assertThat(rotated.decryptBytes(ACME, rewrapped)).isEqualTo("bytes".getBytes());
    }

    @Test
    @DisplayName("two generations of rotation round-trip")
    void twoGenerations() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher = cipherFor(provider, TestKeys.masterRing());

        String gen1 = cipher.encrypt(ACME, "payload");
        provider.add("t2").current("t2");
        String gen2 = cipher.rewrapString(ACME, gen1);
        provider.add("t3").current("t3");
        String gen3 = cipher.rewrapString(ACME, gen2);

        assertThat(cipher.keyIdOf(gen3)).isEqualTo("m1:t3");
        assertThat(cipher.decrypt(ACME, gen3)).isEqualTo("payload");
        // The first generation is still readable: nothing was retired.
        assertThat(cipher.decrypt(ACME, gen1)).isEqualTo("payload");
    }

    @Test
    @DisplayName("retiring a key id before re-wrapping its rows makes them unreadable — the failure to avoid")
    void retiringTooEarly() {
        TestKeys.FixedProvider provider = new TestKeys.FixedProvider("t1");
        TenantCipher cipher = cipherFor(provider, TestKeys.masterRing());
        String orphaned = cipher.encrypt(ACME, "payload");

        // A provider that has forgotten t1 entirely.
        TenantCipher afterRetirement =
                cipherFor(new TestKeys.FixedProvider("t2"), TestKeys.masterRing());

        assertThatExceptionOfType(UnknownKeyException.class)
                .isThrownBy(() -> afterRetirement.decrypt(ACME, orphaned));
    }

    @Test
    @DisplayName("the reference seed provider supports rotation by key id")
    void seedProviderRotation() {
        SeedDerivedKeyProvider provider =
                SeedDerivedKeyProvider.of("a seed long enough to be accepted here", "t1");
        MasterKeyRing ring = TestKeys.masterRing();
        TenantCipher cipher = cipherFor(provider, ring);

        String old = cipher.encrypt(ACME, "payload");

        TenantCipher rotated = cipherFor(provider.rotatedTo("t2"), ring);
        assertThat(rotated.needsRotation(ACME, old)).isTrue();

        String rewrapped = rotated.rewrapString(ACME, old);
        assertThat(rotated.keyIdOf(rewrapped)).isEqualTo("m1:t2");
        assertThat(rotated.decrypt(ACME, rewrapped)).isEqualTo("payload");
    }

    @Test
    @DisplayName("fingerprints must be recomputed on rotation — re-wrapping ciphertext is not enough")
    void fingerprintsNeedRecomputing() {
        SeedDerivedKeyProvider provider =
                SeedDerivedKeyProvider.of("a seed long enough to be accepted here", "t1");
        MasterKeyRing ring = TestKeys.masterRing();

        TenantFingerprint before =
                TenantFingerprint.builder().masterKeys(ring).keyProvider(provider).build();
        String storedFingerprint = before.of(ACME, "a document");

        // Rotate the tenant key generation.
        SeedDerivedKeyProvider rotated = provider.rotatedTo("t2");
        TenantFingerprint after =
                TenantFingerprint.builder().masterKeys(ring).keyProvider(rotated).build();

        // The lookup value has changed, so the stored one no longer matches. A rotation pass that
        // only re-wraps ciphertext leaves every equality lookup silently broken.
        assertThat(after.of(ACME, "a document")).isNotEqualTo(storedFingerprint);
    }

    private static TenantCipher cipherFor(TenantKeyProvider provider, MasterKeyRing ring) {
        return TenantCipher.builder().masterKeys(ring).keyProvider(provider).build();
    }
}
