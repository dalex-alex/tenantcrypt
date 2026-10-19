package io.github.dalexalex.tenantcrypt;

/** Base type for every failure this library raises. */
public class TenantCryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TenantCryptoException(String message) {
        super(message);
    }

    public TenantCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
