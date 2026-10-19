package io.github.dalexalex.tenantcrypt;

import com.google.crypto.tink.DeterministicAead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Deterministic, recoverable encryption for fields you need to <em>search</em>: AES-SIV under a key
 * derived from the server master key and the tenant's data key.
 *
 * <p><strong>This is the default answer to "I encrypted a column and now I cannot query it."</strong>
 * The same plaintext always produces the same bytes for a given tenant and key, so the column
 * compares, joins and indexes normally — and unlike a {@link TenantFingerprint}, the value is
 * recoverable, so one column does both jobs:
 *
 * <pre>{@code
 * String stored = cipher.encrypt(tenant, "alice@example.com");
 *
 * // Look it up: encrypt the probe and compare.
 * repository.findByEmail(cipher.encrypt(tenant, "alice@example.com"));
 *
 * // And read it back.
 * String email = cipher.decrypt(tenant, stored);
 * }</pre>
 *
 * <h2>What determinism costs</h2>
 *
 * Equal plaintexts are <em>visibly equal</em> in the column. That is the feature, and it is also the
 * leak: anyone with the database can see which rows share a value, and how often each distinct
 * value occurs. Over a low-cardinality domain — a status, a country, a boolean — that frequency
 * distribution is usually enough to identify the values without any key at all. **Do not use this
 * for low-cardinality fields.** It suits identifiers: an email address, an account number, a
 * national ID, an external reference.
 *
 * <p>Note also that a value here is recoverable by anyone holding the keys, whereas a fingerprint
 * is one-way. If you want an index that cannot be reversed even with the key, use
 * {@link TenantFingerprint}.
 *
 * <h2>Choosing between this and a fingerprint</h2>
 *
 * Use this unless one of these applies, in which case use {@link TenantFingerprint}:
 *
 * <ul>
 *   <li>The content is too large to index. AES-SIV output is the length of the plaintext plus 16
 *       bytes, so a document-sized value cannot go in a btree index; a fingerprint is 64 characters
 *       whatever the input size.
 *   <li>You need to compare a <em>normalised</em> form — lowercased, whitespace-collapsed — where a
 *       recoverable value would only recover the normalised text and so be useless as data.
 *   <li>You want the searchable column to be irreversible even to a key holder.
 * </ul>
 *
 * <h2>Rotation</h2>
 *
 * Values carry the same versioned header as randomised ciphertext, and — because the header is
 * itself deterministic — a stored value stays directly comparable. So unlike a fingerprint, you can
 * see which key produced a lookup value, find stale rows, and query both generations during a
 * transition. See {@link #needsRotation} and {@link #rewrap}.
 *
 * <p>Thread-safe and intended to be a singleton.
 */
public final class TenantDeterministicCipher {

    private static final int DEFAULT_CACHE_ENTRIES = 1024;

    private static final Envelope.Format FORMAT = Envelope.Format.SIV;

    private final MasterKeyRing masterKeys;
    private final TenantKeyProvider keyProvider;
    private final BoundedCache<TenantKeys.DerivedKey, DeterministicAead> primitives;

    private TenantDeterministicCipher(
            MasterKeyRing masterKeys, TenantKeyProvider keyProvider, int cacheEntries) {
        this.masterKeys = Objects.requireNonNull(masterKeys, "master key ring must not be null");
        this.keyProvider = Objects.requireNonNull(keyProvider, "key provider must not be null");
        this.primitives = new BoundedCache<>(cacheEntries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Encrypts to a base64 envelope. Deterministic: the same arguments always give the same string,
     * which is what makes it usable as a lookup value.
     */
    public String encrypt(TenantId tenant, String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        return Base64.getEncoder()
                .encodeToString(encryptBytes(tenant, plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    /** Decrypts a base64 envelope produced by {@link #encrypt}. */
    public String decrypt(TenantId tenant, String base64Envelope) {
        Objects.requireNonNull(base64Envelope, "ciphertext must not be null");
        return new String(decryptBytes(tenant, TenantKeys.decodeBase64(base64Envelope)), StandardCharsets.UTF_8);
    }

    /** Encrypts to a raw envelope, deterministically. */
    public byte[] encryptBytes(TenantId tenant, byte[] plaintext) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");

        TenantKey tenantKey = TenantKeys.current(keyProvider, tenant);
        String keyId = KeyId.compose(masterKeys.currentVersion(), tenantKey.keyId());
        byte[] aad = Envelope.associatedData(FORMAT.header(keyId), tenant);

        try {
            return FORMAT.encode(
                    keyId,
                    primitiveFor(tenant, keyId, () -> tenantKey)
                            .encryptDeterministically(plaintext, aad));
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException(
                    "deterministic encryption failed for tenant " + tenant.value(), e);
        }
    }

    /** Decrypts a raw envelope produced by {@link #encryptBytes}. */
    public byte[] decryptBytes(TenantId tenant, byte[] envelope) {
        Objects.requireNonNull(tenant, "tenant must not be null");

        Envelope.Parsed parsed = FORMAT.parse(envelope);
        byte[] aad = Envelope.associatedData(parsed.header(), tenant);
        try {
            // Key id comes from the envelope, so the provider is only consulted on a cache miss.
            return primitiveFor(tenant, parsed.keyId(), null)
                    .decryptDeterministically(parsed.body(), aad);
        } catch (GeneralSecurityException e) {
            throw new DecryptionFailedException(
                    "could not decrypt a deterministic value for tenant " + tenant.value()
                            + " under key id '" + parsed.keyId() + "'; the data was modified, or this "
                            + "is the wrong key or the wrong tenant",
                    e);
        }
    }

    /** The key id a stored envelope names, without decrypting it. */
    public String keyIdOf(byte[] envelope) {
        return FORMAT.parse(envelope).keyId();
    }

    /** The key id a stored base64 envelope names, without decrypting it. */
    public String keyIdOf(String base64Envelope) {
        return keyIdOf(TenantKeys.decodeBase64(base64Envelope));
    }

    /**
     * Whether this value was written under something other than the current key.
     *
     * <p>Unlike a fingerprint, a deterministic value records its own key id, so stale rows are
     * findable rather than silently unmatchable. A rotation of either the master key or the tenant
     * key changes every stored value, so a lookup must either run against both generations during
     * the transition or wait until the pass has finished.
     */
    public boolean needsRotation(TenantId tenant, byte[] envelope) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        return !FORMAT.parse(envelope).keyId().equals(currentKeyId(tenant));
    }

    /** As {@link #needsRotation(TenantId, byte[])}, for a base64 envelope. */
    public boolean needsRotation(TenantId tenant, String base64Envelope) {
        return needsRotation(tenant, TenantKeys.decodeBase64(base64Envelope));
    }

    /** Decrypts under the key the envelope names and re-encrypts under the current one. */
    public byte[] rewrap(TenantId tenant, byte[] envelope) {
        return encryptBytes(tenant, decryptBytes(tenant, envelope));
    }

    /** As {@link #rewrap(TenantId, byte[])}, for a base64 envelope. */
    public String rewrapString(TenantId tenant, String base64Envelope) {
        return encrypt(tenant, decrypt(tenant, base64Envelope));
    }

    /** Drops every cached primitive, and with it the derived key material each one holds. */
    public void clearCache() {
        primitives.clear();
    }

    /**
     * The AES-SIV primitive for a key generation, from cache where possible. As with the randomised
     * cipher, the provider is consulted inside the cache-miss path rather than before it.
     */
    private DeterministicAead primitiveFor(TenantId tenant, String keyId, Supplier<TenantKey> known) {
        return primitives.get(
                new TenantKeys.DerivedKey(tenant, keyId),
                unused -> {
                    TenantKey tenantKey =
                            known != null ? known.get() : TenantKeys.resolve(keyProvider, tenant, keyId);
                    return KeyDerivation.deterministicAead(
                            masterKeys.key(KeyId.masterVersionOf(keyId)),
                            tenantKey.material(),
                            Purpose.DETERMINISTIC,
                            tenant);
                });
    }

    private String currentKeyId(TenantId tenant) {
        return KeyId.compose(
                masterKeys.currentVersion(), TenantKeys.current(keyProvider, tenant).keyId());
    }





    public static final class Builder {

        private MasterKeyRing masterKeys;
        private TenantKeyProvider keyProvider;
        private int cacheEntries = DEFAULT_CACHE_ENTRIES;

        private Builder() {}

        /** The server master keys. Required. */
        public Builder masterKeys(MasterKeyRing ring) {
            this.masterKeys = ring;
            return this;
        }

        /** Where per-tenant data keys come from. Required. */
        public Builder keyProvider(TenantKeyProvider provider) {
            this.keyProvider = provider;
            return this;
        }

        /** How many derived primitives to keep. */
        public Builder cacheEntries(int entries) {
            this.cacheEntries = entries;
            return this;
        }

        public TenantDeterministicCipher build() {
            return new TenantDeterministicCipher(masterKeys, keyProvider, cacheEntries);
        }
    }
}
