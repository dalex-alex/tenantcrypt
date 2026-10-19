package io.github.dalexalex.tenantcrypt;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The stored ciphertext layout:
 *
 * <pre>
 *   version[1] || key_id_len[1] || key_id[n] || iv[12] || ciphertext || tag[16]
 * </pre>
 *
 * <p>The header is the part hand-written field encryption usually omits, storing whatever the AEAD
 * emitted instead. Without a key id there is no way to tell which key encrypted a given row, and
 * therefore no rotation, no re-encryption, no algorithm migration and no way to run two keys during
 * a transition. Adding it costs two bytes plus the key id; omitting it cannot be fixed afterwards.
 *
 * <p>The header is also bound as associated data (see {@link #associatedData}), so it cannot be
 * edited without invalidating the tag, and a ciphertext cannot be moved to another tenant and still
 * decrypt.
 *
 * <p>{@code iv || ciphertext || tag} is produced by Tink's AES-GCM with a {@code NO_PREFIX}
 * variant, which emits exactly that layout and nothing else; this class only prepends the header.
 */
final class Envelope {

    private static final byte VERSION_GCM = 0x01;
    private static final byte VERSION_SIV = 0x02;

    private static final int VERSION_OFFSET = 0;
    private static final int KEY_ID_LEN_OFFSET = 1;
    private static final int KEY_ID_OFFSET = 2;

    private Envelope() {}

    /**
     * A stored-value format: its version byte, and the smallest body that version can hold.
     *
     * <p>The two travel together, so they are one thing rather than two arguments every caller has
     * to pair up correctly. A cipher names its format once and then reads and writes through it;
     * mismatching a version with another version's size bound is not expressible.
     */
    enum Format {

        /** Randomised AES-256-GCM. Body is {@code iv[12] || ciphertext || tag[16]}. */
        GCM(VERSION_GCM, 12 + 16, "TenantCipher", "randomised AES-GCM"),

        /**
         * Deterministic AES-SIV. Body is {@code siv_tag[16] || ciphertext}.
         *
         * <p>A separate version rather than a flag, so a deterministic value and a randomised one
         * are never confused: each cipher rejects the other's version by name instead of failing an
         * authentication tag for reasons nobody can diagnose. This is what the version byte was
         * reserved for.
         */
        SIV(VERSION_SIV, 16, "TenantDeterministicCipher", "deterministic AES-SIV");

        private final byte version;
        private final int minBodyLength;
        private final String cipherName;
        private final String description;

        Format(byte version, int minBodyLength, String cipherName, String description) {
            this.version = version;
            this.minBodyLength = minBodyLength;
            this.cipherName = cipherName;
            this.description = description;
        }

        /** The header bytes this format writes for {@code keyId}. */
        byte[] header(String keyId) {
            byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
            if (keyIdBytes.length > KeyId.MAX_LENGTH) {
                throw new IllegalArgumentException(
                        "key id must encode to at most " + KeyId.MAX_LENGTH + " bytes, got "
                                + keyIdBytes.length);
            }
            byte[] header = new byte[KEY_ID_OFFSET + keyIdBytes.length];
            header[VERSION_OFFSET] = version;
            header[KEY_ID_LEN_OFFSET] = (byte) keyIdBytes.length;
            System.arraycopy(keyIdBytes, 0, header, KEY_ID_OFFSET, keyIdBytes.length);
            return header;
        }

        /** {@code header(keyId) || body}. */
        byte[] encode(String keyId, byte[] body) {
            byte[] header = header(keyId);
            byte[] out = new byte[header.length + body.length];
            System.arraycopy(header, 0, out, 0, header.length);
            System.arraycopy(body, 0, out, header.length, body.length);
            return out;
        }

        /**
         * Strict parse. Anything that is not a well-formed envelope of <em>this</em> format is
         * rejected rather than guessed at: there is no fallback format, so a mismatch means the
         * column does not hold what the caller thinks it holds.
         */
        Parsed parse(byte[] envelope) {
            if (envelope == null) {
                throw new MalformedEnvelopeException("envelope must not be null");
            }
            if (envelope.length < KEY_ID_OFFSET) {
                throw new MalformedEnvelopeException(
                        "envelope is " + envelope.length + " bytes, too short to hold a header");
            }
            byte found = envelope[VERSION_OFFSET];
            if (found != version) {
                throw new MalformedEnvelopeException(
                        "expected envelope version 0x" + String.format("%02x", version)
                                + " but found 0x" + String.format("%02x", found) + describe(found));
            }
            int keyIdLength = envelope[KEY_ID_LEN_OFFSET] & 0xFF;
            if (keyIdLength == 0) {
                throw new MalformedEnvelopeException("envelope declares an empty key id");
            }
            int bodyOffset = KEY_ID_OFFSET + keyIdLength;
            int minimum = bodyOffset + minBodyLength;
            if (envelope.length < minimum) {
                throw new MalformedEnvelopeException(
                        "envelope is " + envelope.length + " bytes but declares a " + keyIdLength
                                + "-byte key id, so it needs at least " + minimum);
            }
            return new Parsed(
                    new String(envelope, KEY_ID_OFFSET, keyIdLength, StandardCharsets.UTF_8),
                    Arrays.copyOfRange(envelope, bodyOffset, envelope.length),
                    Arrays.copyOfRange(envelope, 0, bodyOffset));
        }

        /** Names the format a mixed-up column actually holds, so the mistake is obvious. */
        private static String describe(byte version) {
            for (Format format : values()) {
                if (format.version == version) {
                    return " (" + format.description + "). This value was written by "
                            + format.cipherName + "; read it with that, not this one.";
                }
            }
            return ", which this library does not recognise.";
        }
    }

    /**
     * What the AEAD authenticates in addition to the ciphertext: the header exactly as stored, plus
     * the tenant id.
     *
     * <p>Binding the header makes the version and key id tamper-evident. Binding the tenant id
     * means a ciphertext lifted from one tenant's row and dropped into another's fails to decrypt
     * instead of silently succeeding.
     *
     * <p>What this does <em>not</em> bind is the column or the row, because a value does not know
     * where it is stored. Within one tenant, a ciphertext can still be relocated between two
     * columns holding the same kind of value. That limit is in the threat model.
     */
    static byte[] associatedData(byte[] header, TenantId tenant) {
        byte[] tenantBytes = tenant.bytes();
        byte[] aad = new byte[header.length + tenantBytes.length];
        System.arraycopy(header, 0, aad, 0, header.length);
        System.arraycopy(tenantBytes, 0, aad, header.length, tenantBytes.length);
        return aad;
    }

    record Parsed(String keyId, byte[] body, byte[] header) {}
}
