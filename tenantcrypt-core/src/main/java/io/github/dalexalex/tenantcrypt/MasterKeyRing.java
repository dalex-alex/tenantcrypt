package io.github.dalexalex.tenantcrypt;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The server master keys: one per deployment, 32 bytes each, held by version.
 *
 * <p>This is the first of the two HKDF inputs, and the half that is <em>not</em> per-tenant. It
 * comes from the environment or a secret store and is never stored in the database — that is what
 * makes a database leak, on its own, useless.
 *
 * <p>A ring rather than a single key so the master key can rotate: the current version encrypts new
 * data, and older versions stay available to decrypt data that has not been re-wrapped yet. Retire
 * a version only once nothing references it.
 *
 * <p>Immutable; {@link #with} returns a new ring.
 */
public final class MasterKeyRing {

    /** A server master key is always 32 bytes. */
    public static final int KEY_LENGTH = 32;

    private final Map<String, byte[]> keys;
    private final String currentVersion;

    private MasterKeyRing(Map<String, byte[]> keys, String currentVersion) {
        this.keys = keys;
        this.currentVersion = currentVersion;
    }

    /** A ring holding one key, which is also the current one. */
    public static MasterKeyRing of(String version, byte[] key) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        keys.put(KeyId.requireValidMasterPart(version), copyOfValidKey(key, version));
        return new MasterKeyRing(Collections.unmodifiableMap(keys), version);
    }

    /**
     * This ring plus {@code version}, which becomes the current one. The previous keys stay, so
     * data written under them still decrypts.
     */
    public MasterKeyRing with(String version, byte[] key) {
        KeyId.requireValidMasterPart(version);
        Map<String, byte[]> next = new LinkedHashMap<>(keys);
        next.put(version, copyOfValidKey(key, version));
        return new MasterKeyRing(Collections.unmodifiableMap(next), version);
    }

    /** The version new data is encrypted under. */
    public String currentVersion() {
        return currentVersion;
    }

    /** Every version this ring can decrypt under. */
    public Set<String> versions() {
        return keys.keySet();
    }

    byte[] key(String version) {
        byte[] key = keys.get(version);
        if (key == null) {
            throw new UnknownKeyException(
                    "no master key for version '" + version + "'; this ring holds " + keys.keySet()
                            + ". Data encrypted under a retired master key cannot be read.");
        }
        return key;
    }

    private static byte[] copyOfValidKey(byte[] key, String version) {
        Objects.requireNonNull(key, "master key must not be null");
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "master key '" + version + "' must be " + KEY_LENGTH + " bytes, got " + key.length);
        }
        return key.clone();
    }

    @Override
    public String toString() {
        // Never the key material.
        return "MasterKeyRing[versions=" + keys.keySet() + ", current=" + currentVersion + "]";
    }
}
