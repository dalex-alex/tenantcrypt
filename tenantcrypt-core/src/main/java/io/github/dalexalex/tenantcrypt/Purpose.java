package io.github.dalexalex.tenantcrypt;

import java.nio.charset.StandardCharsets;

/**
 * What a derived key is for. The label goes into HKDF's {@code info} parameter, so a key derived
 * for one purpose is cryptographically unrelated to every other — the fingerprint MAC key cannot be
 * used to reason about the field-encryption key or the reverse.
 *
 * <p>This is the cheapest correctness property in the design and the one most often skipped.
 *
 * <p>These labels are part of the stored format, not a configuration knob. Changing one makes every
 * value derived under it undecryptable.
 */
public enum Purpose {

    /** Randomised field and blob encryption, under AES-256-GCM. */
    FIELD("tenantcrypt-field-v1", 32),

    /** Deterministic, recoverable encryption for searchable fields, under AES-SIV. */
    DETERMINISTIC("tenantcrypt-deterministic-v1", 64),

    /** Keyed fingerprints for equality lookups over content too large to index. */
    FINGERPRINT("tenantcrypt-fingerprint-v1", 32);

    private final String label;
    private final int derivedKeyLength;

    Purpose(String label, int derivedKeyLength) {
        this.label = label;
        this.derivedKeyLength = derivedKeyLength;
    }

    public String label() {
        return label;
    }

    /**
     * How many bytes of key material this purpose needs. AES-SIV takes 64 — it is
     * AES-SIV-CMAC-512, which splits its key into a MAC half and an encryption half — while
     * AES-256-GCM and HMAC-SHA256 take 32.
     */
    int derivedKeyLength() {
        return derivedKeyLength;
    }

    byte[] labelBytes() {
        return label.getBytes(StandardCharsets.UTF_8);
    }
}
