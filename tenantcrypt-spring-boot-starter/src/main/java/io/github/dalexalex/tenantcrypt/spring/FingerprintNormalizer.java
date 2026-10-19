package io.github.dalexalex.tenantcrypt.spring;

/**
 * Normalises content before it is fingerprinted, so that values which should be considered the same
 * produce the same fingerprint.
 *
 * <p>This exists because raw equality is usually the wrong question. The same document re-exported
 * through a different producer has different bytes but the same words; OCR is not stable about
 * casing. Without normalisation, de-duplication misses all of that.
 *
 * <p>Returning {@code null} means "do not fingerprint this value" — the fingerprint column is left
 * null. That is the right answer for content too small or too empty to be meaningful: fingerprinting
 * a handful of characters from a failed text extraction would make every near-empty document a
 * duplicate of the first one.
 */
public interface FingerprintNormalizer {

    /**
     * @return the bytes to fingerprint, or null to skip fingerprinting this value
     */
    byte[] normalize(Object value);
}
