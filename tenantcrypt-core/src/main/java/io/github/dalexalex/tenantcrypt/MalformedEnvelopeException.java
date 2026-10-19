package io.github.dalexalex.tenantcrypt;

/**
 * The stored bytes are not a well-formed envelope: wrong version byte, an inconsistent key-id
 * length, or too short to hold an IV and a tag.
 *
 * <p>Distinct from {@link DecryptionFailedException}, which means the envelope parsed but the
 * authentication tag did not verify. The difference matters when diagnosing a bad column: this
 * exception says the data is not ours, the other says the key is wrong or the data was tampered
 * with.
 */
public final class MalformedEnvelopeException extends TenantCryptoException {

    private static final long serialVersionUID = 1L;

    public MalformedEnvelopeException(String message) {
        super(message);
    }
}
