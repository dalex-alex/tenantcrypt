package io.github.dalexalex.tenantcrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/** Deterministic key material, so failures are reproducible. */
final class TestKeys {

    private TestKeys() {}

    /** A deterministic 32-byte value derived from {@code seed}. Tests only. */
    static byte[] bytes32(String seed) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is always present", e);
        }
    }

    static MasterKeyRing masterRing() {
        return MasterKeyRing.of("m1", bytes32("master-1"));
    }

    /**
     * A deliberately broken provider that returns identical key material for every tenant.
     *
     * <p>Exists so isolation tests can prove the library scopes by tenant itself, rather than
     * inheriting that property from a well-behaved provider.
     */
    static TenantKeyProvider sharedKeyProvider() {
        byte[] material = bytes32("one-key-for-everyone");
        return new TenantKeyProvider() {
            @Override
            public TenantKey current(TenantId tenant) {
                return new TenantKey("t1", material);
            }

            @Override
            public TenantKey resolve(TenantId tenant, String keyId) {
                return new TenantKey(keyId, material);
            }
        };
    }

    /** A provider holding fixed keys, with explicit control over which one is current. */
    static final class FixedProvider implements TenantKeyProvider {

        private final Map<String, byte[]> keysById = new HashMap<>();
        private String currentKeyId;

        FixedProvider(String keyId) {
            add(keyId);
            this.currentKeyId = keyId;
        }

        FixedProvider add(String keyId) {
            keysById.put(keyId, bytes32("tenant-key-" + keyId));
            return this;
        }

        FixedProvider current(String keyId) {
            this.currentKeyId = keyId;
            return this;
        }

        @Override
        public TenantKey current(TenantId tenant) {
            return keyFor(tenant, currentKeyId);
        }

        @Override
        public TenantKey resolve(TenantId tenant, String keyId) {
            if (!keysById.containsKey(keyId)) {
                throw new UnknownKeyException("no such test key: " + keyId);
            }
            return keyFor(tenant, keyId);
        }

        /**
         * Per-tenant material, so cross-tenant isolation is actually exercised: if keys did not vary
         * by tenant, a leak between tenants would be invisible.
         */
        private TenantKey keyFor(TenantId tenant, String keyId) {
            byte[] base = keysById.get(keyId);
            byte[] perTenant = bytes32(tenant.value() + ":" + new String(base, StandardCharsets.ISO_8859_1));
            return new TenantKey(keyId, perTenant);
        }
    }
}
