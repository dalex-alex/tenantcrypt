package io.github.dalexalex.tenantcrypt;

import com.google.crypto.tink.Mac;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * A reference {@link TenantKeyProvider} that derives every tenant's data key from one seed:
 *
 * <pre>
 *   tenant_key = HMAC-SHA256( seed, key_id || "/" || tenant_id )
 * </pre>
 *
 * <h2>Not for production. Read this before using it for anything real.</h2>
 *
 * This provider exists so the library can be run, tested and demonstrated without standing up a
 * secret store, and as a worked example of the interface. <strong>It defeats the main property the
 * two-key model exists to provide.</strong>
 *
 * <p>The point of two keys is that neither a database leak nor a single secret-store leak is enough
 * to decrypt anything, because the two keys live in genuinely different trust domains. Here, every
 * tenant key is a pure function of one seed — so that seed and the server master key are a single
 * secret in two parts, and if they sit in the same place (the same {@code .env} file, the same
 * config map, the same environment) then one leak decrypts everything.
 *
 * <p>What it does still preserve is protection against database-level compromise — a stolen backup,
 * an SQL-injection dump, a misconfigured replica — because no key material is ever in the database.
 * That is a real property and it is often the one people actually want. It is not the property this
 * library advertises.
 *
 * <p>In production, implement {@link TenantKeyProvider} against a secret store that holds one
 * independently-generated random key per tenant.
 *
 * <h2>Rotation</h2>
 *
 * Unlike a hard-coded seed, this provider takes a {@code keyId} and mixes it into the derivation,
 * so a new key id yields new key material from the same seed. That makes rotation possible without
 * a second seed: encrypt under a new key id, re-wrap existing rows, then stop resolving the old one.
 * Retaining the old ids is what lets the old rows still be read in the meantime — drop one and the
 * data under it becomes unreadable.
 */
public final class SeedDerivedKeyProvider implements TenantKeyProvider {

    /** Shortest seed this provider will accept. A shorter one is not worth pretending about. */
    public static final int MIN_SEED_LENGTH = 32;

    private final byte[] seed;
    private final String currentKeyId;
    private final java.util.Set<String> knownKeyIds;

    /**
     * Built once from the seed, which is immutable for this provider's lifetime.
     *
     * <p>{@link TenantKeyProvider} is explicit that implementations are called on every encrypt and
     * decrypt and so should cache. Rebuilding a Tink keyset per call — which also draws from
     * {@code SecureRandom} for the keyset's random id — would make the reference implementation an
     * example of the thing its own interface warns against.
     */
    private final Mac seedMac;

    private SeedDerivedKeyProvider(byte[] seed, String currentKeyId, java.util.Set<String> knownKeyIds) {
        this.seed = seed;
        this.currentKeyId = currentKeyId;
        this.knownKeyIds = knownKeyIds;
        this.seedMac = KeyDerivation.seedMac(seed);
    }

    /**
     * A provider over {@code seed} with a single key id, which is also the current one.
     *
     * @param seed at least {@value #MIN_SEED_LENGTH} bytes of secret material
     * @param keyId names this generation of derived keys; it is stored in every ciphertext
     */
    public static SeedDerivedKeyProvider of(byte[] seed, String keyId) {
        Objects.requireNonNull(seed, "seed must not be null");
        if (seed.length < MIN_SEED_LENGTH) {
            throw new IllegalArgumentException(
                    "seed must be at least " + MIN_SEED_LENGTH + " bytes — every tenant key is derived "
                            + "from it — got " + seed.length);
        }
        KeyId.requireValidTenantPart(keyId);
        return new SeedDerivedKeyProvider(seed.clone(), keyId, java.util.Set.of(keyId));
    }

    /** As {@link #of(byte[], String)}, taking the seed as UTF-8 text. */
    public static SeedDerivedKeyProvider of(String seed, String keyId) {
        Objects.requireNonNull(seed, "seed must not be null");
        return of(seed.getBytes(StandardCharsets.UTF_8), keyId);
    }

    /**
     * This provider with {@code keyId} as the current generation, keeping the existing ids
     * resolvable so data already written under them can still be read and re-wrapped.
     */
    public SeedDerivedKeyProvider rotatedTo(String keyId) {
        KeyId.requireValidTenantPart(keyId);
        java.util.Set<String> next = new java.util.LinkedHashSet<>(knownKeyIds);
        next.add(keyId);
        return new SeedDerivedKeyProvider(seed, keyId, java.util.Set.copyOf(next));
    }

    @Override
    public TenantKey current(TenantId tenant) {
        return derive(tenant, currentKeyId);
    }

    @Override
    public TenantKey resolve(TenantId tenant, String keyId) {
        if (!knownKeyIds.contains(keyId)) {
            throw new UnknownKeyException(
                    "this provider does not know key id '" + keyId + "'; it holds " + knownKeyIds
                            + ". Data encrypted under a forgotten key id cannot be read.");
        }
        return derive(tenant, keyId);
    }

    private TenantKey derive(TenantId tenant, String keyId) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        byte[] input = (keyId + "/" + tenant.value()).getBytes(StandardCharsets.UTF_8);
        try {
            return new TenantKey(keyId, seedMac.computeMac(input));
        } catch (GeneralSecurityException e) {
            throw new TenantCryptoException("could not derive a tenant key for " + tenant.value(), e);
        }
    }

    @Override
    public String toString() {
        // Never the seed.
        return "SeedDerivedKeyProvider[current=" + currentKeyId + ", known=" + knownKeyIds + "]";
    }
}
