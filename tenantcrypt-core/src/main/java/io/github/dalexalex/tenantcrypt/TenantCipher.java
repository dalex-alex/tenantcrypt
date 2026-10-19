package io.github.dalexalex.tenantcrypt;

import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Encrypts and decrypts per-tenant values under AES-256-GCM, with a key derived from a server
 * master key and a per-tenant data key. Neither key alone decrypts anything.
 *
 * <p>Every ciphertext carries a header naming the key that produced it, so rotation is an ordinary
 * operation rather than an impossible one — see {@link #needsRotation} and {@link #rewrap}.
 *
 * <p>The tenant is always an explicit parameter. Resolving it from ambient state is right for an
 * application and wrong for a library; if you want that, the Spring module supplies it.
 *
 * <p>Thread-safe and intended to be a singleton.
 *
 * <p><strong>Limits worth knowing.</strong> Random 96-bit IVs are safe to roughly 2<sup>32</sup>
 * messages under one derived key, which is another reason key versioning exists from day one. And
 * no assurance is claimed for this library: no third-party cryptographic review, no audit, one
 * author.
 */
public final class TenantCipher {

    private static final int DEFAULT_CACHE_ENTRIES = 1024;

    private static final Envelope.Format FORMAT = Envelope.Format.GCM;

    private final MasterKeyRing masterKeys;
    private final TenantKeyProvider keyProvider;
    private final BoundedCache<TenantKeys.DerivedKey, Aead> aeads;

    private TenantCipher(MasterKeyRing masterKeys, TenantKeyProvider keyProvider, int cacheEntries) {
        this.masterKeys = Objects.requireNonNull(masterKeys, "master key ring must not be null");
        this.keyProvider = Objects.requireNonNull(keyProvider, "key provider must not be null");
        this.aeads = new BoundedCache<>(cacheEntries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Encrypts to a base64 envelope, for a text column. */
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

    /** Encrypts to a raw envelope, for a binary column. */
    public byte[] encryptBytes(TenantId tenant, byte[] plaintext) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");

        TenantKey tenantKey = TenantKeys.current(keyProvider, tenant);
        String keyId = KeyId.compose(masterKeys.currentVersion(), tenantKey.keyId());
        byte[] aad = Envelope.associatedData(FORMAT.header(keyId), tenant);

        Aead aead = aeadFor(tenant, keyId, () -> tenantKey);
        try {
            return FORMAT.encode(keyId, aead.encrypt(plaintext, aad));
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("encryption failed for tenant " + tenant.value(), e);
        }
    }

    /** Decrypts a raw envelope produced by {@link #encryptBytes}. */
    public byte[] decryptBytes(TenantId tenant, byte[] envelope) {
        Objects.requireNonNull(tenant, "tenant must not be null");

        Envelope.Parsed parsed = FORMAT.parse(envelope);
        // The key id comes from the envelope, so the cache can be consulted without asking the
        // provider first — see aeadFor.
        Aead aead = aeadFor(tenant, parsed.keyId(), null);
        byte[] aad = Envelope.associatedData(parsed.header(), tenant);
        try {
            return aead.decrypt(parsed.body(), aad);
        } catch (GeneralSecurityException e) {
            throw new DecryptionFailedException(
                    "could not decrypt a value for tenant " + tenant.value() + " under key id '"
                            + parsed.keyId() + "'; the data was modified, or this is the wrong key or "
                            + "the wrong tenant",
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
     * Whether this value was encrypted under something other than what {@link #encryptBytes} would
     * use now — either master key version or tenant key. This is the predicate a re-encryption pass
     * selects rows on.
     */
    public boolean needsRotation(TenantId tenant, byte[] envelope) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        return !FORMAT.parse(envelope).keyId().equals(currentKeyId(tenant));
    }

    /** As {@link #needsRotation(TenantId, byte[])}, for a base64 envelope. */
    public boolean needsRotation(TenantId tenant, String base64Envelope) {
        return needsRotation(tenant, TenantKeys.decodeBase64(base64Envelope));
    }

    /**
     * Decrypts under the key the envelope names and re-encrypts under the current one. The
     * plaintext is unchanged; only the key and the header move.
     *
     * <p>This is a primitive, not a migration framework. Driving it over a table — batching,
     * checkpointing, handling failures partway — is the caller's job, and the README documents the
     * pattern.
     *
     * <p>Note that keyed fingerprints are <em>not</em> covered by this. They are derived from the
     * master key too, so rotating it invalidates every fingerprint, and recomputing one needs the
     * plaintext. A rotation pass that re-wraps ciphertext without recomputing fingerprints leaves
     * equality lookups silently broken.
     */
    public byte[] rewrap(TenantId tenant, byte[] envelope) {
        return encryptBytes(tenant, decryptBytes(tenant, envelope));
    }

    /** As {@link #rewrap(TenantId, byte[])}, for a base64 envelope. */
    public String rewrapString(TenantId tenant, String base64Envelope) {
        return encrypt(tenant, decrypt(tenant, base64Envelope));
    }

    /**
     * Drops every cached derived primitive, and with it the key material each one holds. Call this
     * after retiring a key, or when a tenant is offboarded.
     */
    public void clearCache() {
        aeads.clear();
    }

    /**
     * The AES-GCM primitive for a key generation, from cache where possible.
     *
     * <p>{@code known} supplies the tenant key only when one is already in hand (the encrypt path,
     * which had to ask the provider for the current key id anyway). Otherwise the provider is
     * consulted <em>inside</em> the cache-miss path. That ordering matters: a production provider is
     * backed by a secret store, so resolving a key is a network call, and asking before the cache
     * lookup would mean paying for it on every decrypt of an already-warm key.
     */
    private Aead aeadFor(TenantId tenant, String keyId, Supplier<TenantKey> known) {
        return aeads.get(
                new TenantKeys.DerivedKey(tenant, keyId),
                unused -> {
                    TenantKey tenantKey =
                            known != null ? known.get() : TenantKeys.resolve(keyProvider, tenant, keyId);
                    return KeyDerivation.aead(
                            masterKeys.key(KeyId.masterVersionOf(keyId)),
                            tenantKey.material(),
                            Purpose.FIELD,
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

        /**
         * How many derived primitives to keep. Defaults to {@value #DEFAULT_CACHE_ENTRIES}; size it
         * to the number of tenants you expect to be active at once.
         */
        public Builder cacheEntries(int entries) {
            this.cacheEntries = entries;
            return this;
        }

        public TenantCipher build() {
            return new TenantCipher(masterKeys, keyProvider, cacheEntries);
        }
    }
}
