package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.TenantCryptoException;

/**
 * An encrypted or fingerprinted field was read or written with no tenant in {@link TenantContext}.
 *
 * <p>Almost always means work ran off the request path — a scheduled job, a message consumer, a
 * post-commit hook, an async dispatch — without wrapping itself in
 * {@link TenantContext#withTenant}.
 */
public final class MissingTenantContextException extends TenantCryptoException {

    private static final long serialVersionUID = 1L;

    public MissingTenantContextException(String message) {
        super(message);
    }
}
