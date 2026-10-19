package io.github.dalexalex.tenantcrypt.spring;

import jakarta.persistence.AttributeConverter;

/**
 * Encrypts a {@code String} attribute to a base64 envelope in a text column.
 *
 * <p>Usable two ways. Either portably, with plain JPA:
 *
 * <pre>{@code
 * @Convert(converter = EncryptedStringConverter.class)
 * private String content;
 * }</pre>
 *
 *
 * <p><strong>Two consequences worth knowing before adding this to a column.</strong>
 *
 * <p>First, decryption moves inside the persistence provider's hydration rather than a call site you
 * chose, and the exception does not arrive as itself: Hibernate catches it and rethrows "Error
 * attempting to apply AttributeConverter", which Spring translates again, so what reaches your code
 * is a {@code JpaSystemException} with {@code DecryptionFailedException} somewhere in its cause
 * chain. Catch it by walking the causes. A row that cannot be decrypted fails every query loading
 * that entity, not only the code that wanted the field; {@code tenantcrypt.fail-soft-reads} makes
 * such a value read as null instead.
 *
 * <p>Second, <strong>the column can no longer be queried.</strong> Encryption is randomised, so
 * {@code WHERE content = ?} will never match, {@code LIKE} is meaningless, and an index on it is
 * useless. If you need equality lookups, pair the field with a {@link Fingerprint} column. Widen
 * the column too: base64 of a versioned envelope is materially longer than the plaintext.
 */
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return TenantConverters.toColumn(attribute, TenantCryptoRuntime.cipher()::encrypt);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return TenantConverters.toAttribute(dbData, TenantCryptoRuntime.cipher()::decrypt);
    }
}
