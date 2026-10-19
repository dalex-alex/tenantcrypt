package io.github.dalexalex.tenantcrypt;

import com.google.crypto.tink.Mac;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Keyed fingerprints: a deterministic, tenant-scoped value you can put in a plaintext indexed
 * column and compare, for content that stays encrypted at rest.
 *
 * <h2>The problem this solves</h2>
 *
 * AES-GCM is randomised. A fresh IV per call means the same plaintext produces different ciphertext
 * every time, so <strong>ciphertext can never be compared for equality</strong>. Every feature that
 * needs "have I seen this content before" — de-duplication, idempotency, join keys, uniqueness —
 * breaks the moment the column is encrypted, and teams usually discover this after encrypting it.
 *
 * <p>The fix is a second key, derived under a different purpose label, used for a keyed MAC over
 * the content:
 *
 * <pre>
 *   fingerprint = HMAC-SHA256( HKDF(master || tenant_key, info="...fingerprint-v1"), content )
 * </pre>
 *
 * <p>Deterministic, so it lives in an ordinary indexed column and is compared and joined normally.
 * <strong>Keyed</strong>, so unlike a bare SHA-256 it does not let someone holding a database dump
 * confirm that a document they already possess is present. <strong>Tenant-scoped</strong>, because
 * the tenant id is mixed into the key derivation itself — so identical content under two tenants
 * produces different fingerprints even if a key provider mistakenly hands both tenants the same key
 * material. And derived under a distinct purpose label, so this key cannot decrypt anything and the
 * encryption key cannot forge fingerprints.
 *
 * <h2>When not to use it</h2>
 *
 * A deterministic value over a low-entropy domain is guessable by anyone who <em>also</em> holds the
 * key. Fingerprints suit high-entropy content: documents, blobs, file bytes. For a low-cardinality
 * field — a status, a country, a boolean — a deterministic value leaks the distribution even when
 * keyed, and the answer is not to fingerprint it.
 *
 * <h2>Rotation</h2>
 *
 * The key is derived from both the master key and the tenant's data key, so rotating either changes
 * every fingerprint: the same plaintext MACs to a different value. Nothing is lost — the input is
 * plaintext and is still there — but a stored fingerprint computed under a retired key will no
 * longer match a freshly computed one, so a rotation pass has to <em>recompute</em> fingerprints
 * from the plaintext, not merely re-wrap ciphertext the way {@code TenantCipher.rewrap} does.
 *
 * <p>Because a lookup value has to be byte-equal to what is stored, a fingerprint cannot carry a
 * parsed header the way a ciphertext envelope does. What it carries instead is a plain prefix:
 *
 * <pre>
 *   m1:t1:13623a4dada1d20f52b2888e78c5543e2a53c0fbce5982f934efc765ff2abd13
 *   ^^^^^ key generation            ^^ 64 hex characters of HMAC-SHA256
 * </pre>
 *
 * <p>Still deterministic, still a single indexable column, and now a stale row is <em>findable</em>
 * rather than silently unmatchable — {@code WHERE fp NOT LIKE 'm1:t1:%'} selects exactly the rows a
 * recompute pass still owes. Without it, a skipped pass makes every lookup return nothing, which is
 * indistinguishable from the content genuinely being absent. That is the same defect the versioned
 * ciphertext envelope exists to prevent.
 *
 * <p>{@link #under} computes a named generation, so a transitional query can look for either.
 *
 * <p>Thread-safe and intended to be a singleton.
 */
public final class TenantFingerprint {

    private static final int DEFAULT_CACHE_ENTRIES = 1024;
    private static final HexFormat HEX = HexFormat.of();

    /** HMAC-SHA256, hex encoded. */
    private static final int HEX_LENGTH = 64;

    private final MasterKeyRing masterKeys;
    private final TenantKeyProvider keyProvider;
    private final BoundedCache<TenantKeys.DerivedKey, Mac> macs;

    private TenantFingerprint(
            MasterKeyRing masterKeys, TenantKeyProvider keyProvider, int cacheEntries) {
        this.masterKeys = Objects.requireNonNull(masterKeys, "master key ring must not be null");
        this.keyProvider = Objects.requireNonNull(keyProvider, "key provider must not be null");
        this.macs = new BoundedCache<>(cacheEntries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * The fingerprint of {@code content} for {@code tenant}, under the tenant's current key, as
     * {@code <keyGeneration>:<64 hex characters>}.
     */
    public String of(TenantId tenant, byte[] content) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        TenantKey key = TenantKeys.current(keyProvider, tenant);
        return compute(
                tenant, KeyId.compose(masterKeys.currentVersion(), key.keyId()), () -> key, content);
    }

    /** The fingerprint of {@code content} encoded as UTF-8. */
    public String of(TenantId tenant, String content) {
        Objects.requireNonNull(content, "content must not be null");
        return of(tenant, content.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The fingerprint of {@code content} under a named key generation, for example {@code m1:t1}.
     *
     * <p>Two uses. During a rotation, a lookup can search both generations at once
     * ({@code WHERE fp IN (:current, :previous)}) instead of missing rows the pass has not reached.
     * And a recompute pass can verify it reproduces what is stored before overwriting it.
     *
     * @throws UnknownKeyException if the provider cannot supply that generation
     */
    public String under(TenantId tenant, String keyId, byte[] content) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        Objects.requireNonNull(keyId, "key id must not be null");
        // The generation is named by the caller, so the provider is only consulted on a cache miss.
        return compute(tenant, keyId, null, content);
    }

    /** As {@link #under(TenantId, String, byte[])}, for content encoded as UTF-8. */
    public String under(TenantId tenant, String keyId, String content) {
        Objects.requireNonNull(content, "content must not be null");
        return under(tenant, keyId, content.getBytes(StandardCharsets.UTF_8));
    }

    /** The key generation a stored fingerprint was computed under. */
    public String keyIdOf(String fingerprint) {
        Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        int at = fingerprint.lastIndexOf(KeyId.SEPARATOR);
        if (at < 1 || fingerprint.length() - at - 1 != HEX_LENGTH) {
            throw new MalformedEnvelopeException(
                    "'" + fingerprint + "' is not a tenantcrypt fingerprint; expected "
                            + "<keyGeneration>:<" + HEX_LENGTH + " hex characters>");
        }
        return fingerprint.substring(0, at);
    }

    /**
     * Whether a stored fingerprint was computed under a retired key and so needs recomputing.
     *
     * <p>This is the predicate a recompute pass selects on, and the thing an unprefixed fingerprint
     * made impossible to ask.
     */
    public boolean needsRotation(TenantId tenant, String fingerprint) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        return !keyIdOf(fingerprint).equals(currentKeyId(tenant));
    }

    private String compute(
            TenantId tenant, String keyId, Supplier<TenantKey> known, byte[] content) {
        Objects.requireNonNull(content, "content must not be null");
        try {
            return keyId
                    + KeyId.SEPARATOR
                    + HEX.formatHex(macFor(tenant, keyId, known).computeMac(content));
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException(
                    "could not compute a fingerprint for tenant " + tenant.value(), e);
        }
    }

    /** Drops every cached MAC primitive, and with it the derived key material each one holds. */
    public void clearCache() {
        macs.clear();
    }

    private Mac macFor(TenantId tenant, String keyId, Supplier<TenantKey> known) {
        return macs.get(
                new TenantKeys.DerivedKey(tenant, keyId),
                unused -> {
                    TenantKey tenantKey =
                            known != null ? known.get() : TenantKeys.resolve(keyProvider, tenant, keyId);
                    return KeyDerivation.mac(
                            masterKeys.key(KeyId.masterVersionOf(keyId)),
                            tenantKey.material(),
                            Purpose.FINGERPRINT,
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

        /** How many derived MAC primitives to keep. */
        public Builder cacheEntries(int entries) {
            this.cacheEntries = entries;
            return this;
        }

        public TenantFingerprint build() {
            return new TenantFingerprint(masterKeys, keyProvider, cacheEntries);
        }
    }
}
