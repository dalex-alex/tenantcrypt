package io.github.dalexalex.tenantcrypt;

/**
 * A {@link TenantKeyProvider} could not supply the key a stored envelope names.
 *
 * <p>This is the failure that matters most operationally: it means data exists that was encrypted
 * under a key the provider has forgotten. Retiring a key before every row referencing it has been
 * re-wrapped produces exactly this, which is why {@link TenantCipher#keyIdOf} exists.
 */
public final class UnknownKeyException extends TenantCryptoException {

    private static final long serialVersionUID = 1L;

    public UnknownKeyException(String message) {
        super(message);
    }

    public UnknownKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
