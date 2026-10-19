package io.github.dalexalex.tenantcrypt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/**
 * The two-input derivation, and the Tink primitives built on top of it. This is the heart of the
 * library; everything else is plumbing around it.
 *
 * <pre>
 *   derived_key = HKDF-SHA256( ikm  = server_master_key || tenant_data_key,
 *                              salt = none,
 *                              info = purpose label )
 * </pre>
 *
 * <p><strong>Why both keys are concatenated into {@code ikm} with no salt.</strong> The
 * conventional HKDF construction passes one key as {@code ikm} and the other as {@code salt}; this
 * does not. The reason: HKDF-Extract with an absent salt is defined by
 * RFC 5869 (it is treated as {@code HashLen} zero bytes), both inputs here are full-entropy 32-byte
 * keys rather than one key and one public value, and {@code info} already separates the key uses.
 * Extract over the concatenation therefore mixes both inputs into the pseudorandom key exactly as
 * intended, and the security argument does not depend on which parameter each key arrives in.
 * Passing the master key as {@code salt} would be equally sound and no stronger.
 *
 * <p>Primitives are built with the {@code NO_PREFIX} variant so Tink emits bare
 * {@code iv || ciphertext || tag} and a bare MAC tag, with no Tink key-id prefix of its own. This
 * library carries its own header instead ({@link Envelope}), which is what keeps key ids
 * human-readable and independent of Tink's internal key numbering.
 */
final class KeyDerivation {

    /** HKDF-SHA256 over the 64-byte concatenation of the two keys. */
    private static final int IKM_LENGTH = MasterKeyRing.KEY_LENGTH + TenantKey.MATERIAL_LENGTH;

    static {
        try {
            AeadConfig.register();
            DeterministicAeadConfig.register();
            MacConfig.register();
            PrfConfig.register();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not register Tink primitives", e);
        }
    }

    private KeyDerivation() {}

    /** An AES-256-GCM primitive for {@code purpose}, keyed by the two-input derivation. */
    static Aead aead(byte[] masterKey, byte[] tenantKey, Purpose purpose, TenantId tenant) {
        byte[] derived = derive(masterKey, tenantKey, purpose, tenant);
        try {
            return handle(aesGcmKey(derived)).getPrimitive(RegistryConfiguration.get(), Aead.class);
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not build an AES-GCM primitive", e);
        }
    }

    /**
     * An AES-SIV primitive for {@code purpose}, keyed by the two-input derivation.
     *
     * <p>Deterministic: the same plaintext, tenant and key always produce the same bytes, which is
     * what makes the column comparable and indexable.
     */
    static DeterministicAead deterministicAead(byte[] masterKey, byte[] tenantKey, Purpose purpose, TenantId tenant) {
        byte[] derived = derive(masterKey, tenantKey, purpose, tenant);
        try {
            return handle(aesSivKey(derived))
                    .getPrimitive(RegistryConfiguration.get(), DeterministicAead.class);
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not build an AES-SIV primitive", e);
        }
    }

    /** An HMAC-SHA256 primitive for {@code purpose}, keyed by the two-input derivation. */
    static Mac mac(byte[] masterKey, byte[] tenantKey, Purpose purpose, TenantId tenant) {
        byte[] derived = derive(masterKey, tenantKey, purpose, tenant);
        try {
            return handle(hmacKey(derived)).getPrimitive(RegistryConfiguration.get(), Mac.class);
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not build an HMAC primitive", e);
        }
    }

    /**
     * An HMAC-SHA256 primitive keyed directly on {@code seed}.
     *
     * <p>Not part of the two-input derivation — this exists for
     * {@link SeedDerivedKeyProvider}, which derives tenant keys from a single seed and is
     * explicitly not a production key source.
     */
    @AccessesPartialKey
    static Mac seedMac(byte[] seed) {
        try {
            HmacParameters parameters =
                    HmacParameters.builder()
                            .setKeySizeBytes(seed.length)
                            .setTagSizeBytes(32)
                            .setHashType(HmacParameters.HashType.SHA256)
                            .setVariant(HmacParameters.Variant.NO_PREFIX)
                            .build();
            HmacKey key =
                    HmacKey.builder()
                            .setParameters(parameters)
                            .setKeyBytes(SecretBytes.copyFrom(seed, InsecureSecretKeyAccess.get()))
                            .build();
            return handle(key).getPrimitive(RegistryConfiguration.get(), Mac.class);
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not build a seed HMAC primitive", e);
        }
    }

    @AccessesPartialKey
    private static byte[] derive(byte[] masterKey, byte[] tenantKey, Purpose purpose, TenantId tenant) {
        byte[] ikm = new byte[IKM_LENGTH];
        System.arraycopy(masterKey, 0, ikm, 0, MasterKeyRing.KEY_LENGTH);
        System.arraycopy(tenantKey, 0, ikm, MasterKeyRing.KEY_LENGTH, TenantKey.MATERIAL_LENGTH);
        try {
            HkdfPrfParameters parameters =
                    HkdfPrfParameters.builder()
                            .setKeySizeBytes(IKM_LENGTH)
                            .setHashType(HkdfPrfParameters.HashType.SHA256)
                            .setSalt(Bytes.copyFrom(new byte[0]))
                            .build();
            HkdfPrfKey key =
                    HkdfPrfKey.builder()
                            .setParameters(parameters)
                            .setKeyBytes(SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()))
                            .build();
            PrfSet prfs = handle(key).getPrimitive(RegistryConfiguration.get(), PrfSet.class);
            return prfs.computePrimary(info(purpose, tenant), purpose.derivedKeyLength());
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not derive a key for purpose " + purpose, e);
        }
    }

    /**
     * HKDF's {@code info}: the purpose label, then the tenant id.
     *
     * <p>Binding the tenant here makes tenant isolation a property of the derivation rather than a
     * promise the key provider has to keep. A provider that mistakenly hands the same key material
     * to every tenant is a plausible bug — and without this, it would silently produce identical
     * fingerprints for identical content across tenants, which is exactly the cross-tenant
     * confirmation the keyed fingerprint exists to prevent. Ciphertext already had this property
     * through the associated data; this gives fingerprints the same guarantee.
     *
     * <p>Unambiguous because purpose labels are a closed set containing no {@code /}, so no
     * label-plus-tenant pair can collide with another.
     */
    private static byte[] info(Purpose purpose, TenantId tenant) {
        return (purpose.label() + "/" + tenant.value()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    @AccessesPartialKey
    private static AesGcmKey aesGcmKey(byte[] derived) throws GeneralSecurityException {
        AesGcmParameters parameters =
                AesGcmParameters.builder()
                        .setKeySizeBytes(Purpose.FIELD.derivedKeyLength())
                        .setIvSizeBytes(12)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build();
        return AesGcmKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.copyFrom(derived, InsecureSecretKeyAccess.get()))
                .build();
    }

    @AccessesPartialKey
    private static AesSivKey aesSivKey(byte[] derived) throws GeneralSecurityException {
        AesSivParameters parameters =
                AesSivParameters.builder()
                        .setKeySizeBytes(Purpose.DETERMINISTIC.derivedKeyLength())
                        .setVariant(AesSivParameters.Variant.NO_PREFIX)
                        .build();
        return AesSivKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.copyFrom(derived, InsecureSecretKeyAccess.get()))
                .build();
    }

    @AccessesPartialKey
    private static HmacKey hmacKey(byte[] derived) throws GeneralSecurityException {
        HmacParameters parameters =
                HmacParameters.builder()
                        .setKeySizeBytes(Purpose.FINGERPRINT.derivedKeyLength())
                        .setTagSizeBytes(32)
                        .setHashType(HmacParameters.HashType.SHA256)
                        .setVariant(HmacParameters.Variant.NO_PREFIX)
                        .build();
        return HmacKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.copyFrom(derived, InsecureSecretKeyAccess.get()))
                .build();
    }

    private static KeysetHandle handle(com.google.crypto.tink.Key key) throws GeneralSecurityException {
        return KeysetHandle.newBuilder()
                .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
                .build();
    }
}
