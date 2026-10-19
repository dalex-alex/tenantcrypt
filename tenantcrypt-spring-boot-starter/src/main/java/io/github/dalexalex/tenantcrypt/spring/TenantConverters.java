package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.DecryptionFailedException;
import io.github.dalexalex.tenantcrypt.TenantId;
import java.util.function.BiFunction;

/**
 * The read and write halves shared by every {@code AttributeConverter} in this module.
 *
 * <p>Both halves are the same in all of them: pass null through untouched, resolve the ambient
 * tenant, and — on the read side — honour the fail-soft setting. Keeping that in one place matters
 * more than the line count suggests, because fail-soft reads are a safety behaviour and three
 * hand-copied versions of it is three places for one to drift.
 */
final class TenantConverters {

    private TenantConverters() {}

    /** Encrypts a non-null attribute under the ambient tenant. */
    static <T> T toColumn(T attribute, BiFunction<TenantId, T, T> encrypt) {
        if (attribute == null) {
            return null;
        }
        return encrypt.apply(TenantContext.currentOrThrow(), attribute);
    }

    /**
     * Decrypts a non-null column value under the ambient tenant.
     *
     * <p>When {@code tenantcrypt.fail-soft-reads} is on, a value that does not decrypt reads as
     * null instead of throwing — for read paths that would rather skip an unreadable row than fail
     * the whole query.
     */
    static <T> T toAttribute(T dbData, BiFunction<TenantId, T, T> decrypt) {
        if (dbData == null) {
            return null;
        }
        try {
            return decrypt.apply(TenantContext.currentOrThrow(), dbData);
        } catch (DecryptionFailedException e) {
            if (TenantCryptoRuntime.failSoftReads()) {
                return null;
            }
            throw e;
        }
    }
}
