package io.github.dalexalex.tenantcrypt;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The envelope's key id: {@code <masterKeyVersion>:<tenantKeyId>}.
 *
 * <p>One opaque string as far as the format is concerned, but composed of both halves of the
 * derivation, because both can rotate independently and a ciphertext has to name the pair it was
 * produced under. Neither half may contain {@code :}, and the whole thing is length-prefixed with a
 * single byte, so it is capped at 255 bytes.
 *
 * <p>Key ids appear in stored data, which makes their spelling a public contract. Pick a scheme
 * before writing data, not after.
 */
final class KeyId {

    /** The key id is length-prefixed by a single byte. */
    static final int MAX_LENGTH = 255;

    /** Separates the two halves of a composed key id, and a fingerprint from its generation. */
    static final char SEPARATOR = ':';

    private KeyId() {}

    static String compose(String masterKeyVersion, String tenantKeyId) {
        String composed = masterKeyVersion + SEPARATOR + tenantKeyId;
        int length = composed.getBytes(StandardCharsets.UTF_8).length;
        if (length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "key id must encode to at most " + MAX_LENGTH + " bytes, got " + length + ": " + composed);
        }
        return composed;
    }

    static String masterVersionOf(String keyId) {
        int at = keyId.indexOf(SEPARATOR);
        if (at < 0) {
            throw new MalformedEnvelopeException(
                    "key id '" + keyId + "' is not <masterKeyVersion>:<tenantKeyId>");
        }
        return keyId.substring(0, at);
    }

    static String tenantPartOf(String keyId) {
        int at = keyId.indexOf(SEPARATOR);
        if (at < 0) {
            throw new MalformedEnvelopeException(
                    "key id '" + keyId + "' is not <masterKeyVersion>:<tenantKeyId>");
        }
        return keyId.substring(at + 1);
    }

    static String requireValidTenantPart(String tenantKeyId) {
        return requireValidPart(tenantKeyId, "tenant key id");
    }

    static String requireValidMasterPart(String masterKeyVersion) {
        return requireValidPart(masterKeyVersion, "master key version");
    }

    private static String requireValidPart(String part, String what) {
        Objects.requireNonNull(part, what + " must not be null");
        if (part.isEmpty()) {
            throw new IllegalArgumentException(what + " must not be empty");
        }
        if (part.indexOf(SEPARATOR) >= 0) {
            throw new IllegalArgumentException(
                    what + " must not contain '" + SEPARATOR + "' — it separates the two halves of the "
                            + "stored key id, got: " + part);
        }
        return part;
    }
}
