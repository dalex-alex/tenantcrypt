package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.TenantCryptoException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/** The normalisers {@link Fingerprint} can use. */
public final class Normalizers {

    private Normalizers() {}

    /**
     * The bytes of a value that has a stable, value-based representation.
     *
     * <p>Only {@code byte[]} and {@code CharSequence} are accepted. Anything else is refused rather
     * than passed through {@code toString()}, because a type without a value-based
     * {@code toString()} — an array, or any object that does not override it — yields its identity
     * hash, which differs between two equal values and between JVM runs. Fingerprinting that
     * produces a deterministic-looking value that is silently nondeterministic: de-duplication
     * would simply never match, and nothing would report an error.
     *
     * <p>This library's whole premise is that a silent crypto failure is the dangerous one, so the
     * ambiguous case is a hard failure with instructions rather than a guess.
     */
    static byte[] bytesOf(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        if (value instanceof CharSequence text) {
            return text.toString().getBytes(StandardCharsets.UTF_8);
        }
        throw new TenantCryptoException(
                "cannot fingerprint a value of type " + value.getClass().getName()
                        + ": a fingerprint has to be computed over a stable, value-based byte "
                        + "representation, and this type has none that can be assumed. Fingerprint a "
                        + "String or byte[] field, or supply a FingerprintNormalizer that converts "
                        + "this type explicitly.");
    }

    /**
     * Fingerprints the value as-is: {@code byte[]} unchanged, {@code CharSequence} as its UTF-8
     * bytes. The right choice for file bytes, where the exact content is the identity.
     */
    public static final class Exact implements FingerprintNormalizer {

        @Override
        public byte[] normalize(Object value) {
            return bytesOf(value);
        }
    }

    /**
     * Lowercases and collapses runs of whitespace to a single space, then trims.
     *
     * <p>For text extracted from documents: a re-export re-flows whitespace and line breaks but not
     * words, and OCR is inconsistent about case. Normalising both means the same document still
     * matches itself.
     *
     * <p>A {@code byte[]} is decoded as UTF-8 first, so this behaves identically whether the text
     * arrives as a {@code String} or as the bytes of one.
     */
    public static final class Text implements FingerprintNormalizer {

        private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s+");

        @Override
        public byte[] normalize(Object value) {
            byte[] raw = bytesOf(value);
            if (raw == null) {
                return null;
            }
            String normalized =
                    WHITESPACE_RUN
                            .matcher(new String(raw, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT))
                            .replaceAll(" ")
                            .trim();
            return normalized.getBytes(StandardCharsets.UTF_8);
        }
    }
}
