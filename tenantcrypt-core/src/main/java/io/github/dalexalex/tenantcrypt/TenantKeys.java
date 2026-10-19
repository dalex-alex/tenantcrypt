package io.github.dalexalex.tenantcrypt;

import java.util.Base64;

/**
 * Shared plumbing between the three ciphers: asking a {@link TenantKeyProvider} for a key and
 * translating whatever it does into this library's own failures.
 *
 * <p>This lives once rather than in each cipher because it is the behaviour of the
 * provider <em>relationship</em>, not of any one cipher. A change to how a provider failure is
 * classified should not be a change that has to be found in three places and missed in one.
 */
final class TenantKeys {

    private TenantKeys() {}

    static TenantKey current(TenantKeyProvider provider, TenantId tenant) {
        return require(provider.current(tenant), tenant, null);
    }

    /**
     * The key a stored value names, resolved by the tenant-scoped half of its composed key id.
     *
     * <p>A provider that throws something of its own — an HTTP failure, a missing secret — is
     * translated to {@link UnknownKeyException}, because from the caller's point of view the
     * distinction that matters is "this data names a key we cannot get", not which client library
     * reported it.
     */
    static TenantKey resolve(TenantKeyProvider provider, TenantId tenant, String keyId) {
        String tenantPart = KeyId.tenantPartOf(keyId);
        TenantKey key;
        try {
            key = provider.resolve(tenant, tenantPart);
        } catch (UnknownKeyException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new UnknownKeyException(
                    "key provider failed to resolve key '" + tenantPart + "' for tenant "
                            + tenant.value(),
                    e);
        }
        return require(key, tenant, tenantPart);
    }

    /** Decodes a stored base64 value, reporting a non-base64 column as a malformed envelope. */
    static byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new MalformedEnvelopeException("value is not valid base64: " + e.getMessage());
        }
    }

    private static TenantKey require(TenantKey key, TenantId tenant, String keyId) {
        if (key == null) {
            throw new UnknownKeyException(
                    "key provider returned no key for tenant " + tenant.value()
                            + (keyId == null ? "" : " and key id '" + keyId + "'"));
        }
        return key;
    }

    /**
     * Identifies a derived primitive: the tenant it belongs to and the key generation it came from.
     *
     * <p>A record rather than a delimited string, so there is no separator to escape and no way for
     * two different pairs to collide on one cache key.
     */
    record DerivedKey(String tenant, String keyId) {

        DerivedKey(TenantId tenant, String keyId) {
            this(tenant.value(), keyId);
        }
    }
}
