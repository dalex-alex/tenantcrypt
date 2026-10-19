package io.github.dalexalex.tenantcrypt.spring;

import jakarta.persistence.AttributeConverter;

/**
 * Encrypts a {@code byte[]} attribute to a raw envelope in a binary column — the shape a stored
 * file or PDF takes.
 *
 * <p>Raw rather than base64, because a {@code bytea} or {@code blob} column has no reason to pay
 * the 33% base64 overhead.
 *
 * <p>Apply it with {@code @Convert(converter = EncryptedBytesConverter.class)}.
 */
public class EncryptedBytesConverter implements AttributeConverter<byte[], byte[]> {

    @Override
    public byte[] convertToDatabaseColumn(byte[] attribute) {
        if (attribute == null) {
            return null;
        }
        return TenantCryptoRuntime.cipher().encryptBytes(TenantContext.currentOrThrow(), attribute);
    }

    @Override
    public byte[] convertToEntityAttribute(byte[] dbData) {
        return TenantConverters.toAttribute(dbData, TenantCryptoRuntime.cipher()::decryptBytes);
    }
}
