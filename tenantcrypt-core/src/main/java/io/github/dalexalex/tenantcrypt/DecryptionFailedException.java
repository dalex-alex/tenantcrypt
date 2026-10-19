package io.github.dalexalex.tenantcrypt;

/**
 * The envelope parsed but did not authenticate. Either the ciphertext was modified, or it is being
 * decrypted under the wrong key, the wrong tenant, or a tampered header — the associated data binds
 * all three, so any mismatch surfaces here rather than as silently wrong plaintext.
 */
public final class DecryptionFailedException extends TenantCryptoException {

    private static final long serialVersionUID = 1L;

    public DecryptionFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
