package io.github.dalexalex.tenantcrypt;

import java.util.Objects;

/**
 * A tenant's data key: 32 bytes of key material, plus the id under which this library records it in
 * every ciphertext it produces.
 *
 * <p>This is the second of the two HKDF inputs. It is never sufficient on its own — the server
 * master key is the other half, and neither alone decrypts anything.
 *
 * <p>Not a record, deliberately: the material is copied in and out so a caller cannot mutate key
 * bytes this object is still holding.
 */
public final class TenantKey {

    /** A tenant data key is always 32 bytes. */
    public static final int MATERIAL_LENGTH = 32;

    private final String keyId;
    private final byte[] material;

    public TenantKey(String keyId, byte[] material) {
        this.keyId = KeyId.requireValidTenantPart(keyId);
        Objects.requireNonNull(material, "key material must not be null");
        if (material.length != MATERIAL_LENGTH) {
            throw new IllegalArgumentException(
                    "tenant key material must be " + MATERIAL_LENGTH + " bytes, got " + material.length);
        }
        this.material = material.clone();
    }

    /**
     * Identifies this key generation within the tenant, for example {@code t1} or {@code 2026-09}.
     * It is stored in every ciphertext, so it must stay resolvable for as long as data encrypted
     * under it exists, and it must not contain {@code :} — that separates it from the master key
     * version in the envelope.
     */
    public String keyId() {
        return keyId;
    }

    /** A copy of the key material. */
    public byte[] material() {
        return material.clone();
    }

    @Override
    public String toString() {
        // Never the material.
        return "TenantKey[keyId=" + keyId + "]";
    }

}
