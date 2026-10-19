package io.github.dalexalex.tenantcrypt.spring;

import jakarta.persistence.AttributeConverter;

/**
 * Encrypts a {@code String} attribute deterministically, so the column stays searchable.
 *
 * <p>Usable portably with plain JPA:
 *
 * <pre>{@code
 * @Convert(converter = DeterministicStringConverter.class)
 * private String email;
 * }</pre>
 *
 * <p>Because the mapping is deterministic, JPA applies this converter to query parameters as well
 * as to stored values — so a derived repository method such as {@code findByEmail(String)} keeps
 * working against the encrypted column with no change at the call site. No second column, no
 * fingerprint, and the value is still recoverable.
 *
 * <p>For a value you do not need to search, use {@link EncryptedStringConverter} instead: it is
 * randomised, and so leaks nothing about which rows share a value.
 *
 * <h2>What determinism leaks — read before adding this to a column</h2>
 *
 * Equal plaintexts are <strong>visibly equal</strong> in the column. That is the feature and it is
 * also the cost: anyone with the database can see which rows share a value and how often each
 * distinct value occurs, without any key.
 *
 * <p><strong>Never use this on a low-cardinality column.</strong> For a status, a country, a
 * boolean or a tier, the frequency distribution alone usually identifies the values. It suits
 * high-cardinality identifiers: an email address, an account number, a national ID, an external
 * reference.
 *
 * <p>Ordering and range queries do not work — ciphertext order is unrelated to plaintext order.
 * Only equality; {@code LIKE} and prefix matching do not work either.
 *
 * <h2>Rotation</h2>
 *
 * Stored values carry their key id, so after a rotation stale rows are findable and a transition can
 * query both generations. But rotating either key <em>changes every stored value</em>, so lookups
 * must run against both generations until the re-encryption pass completes.
 */
public class DeterministicStringConverter implements AttributeConverter<String, String> {

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return TenantConverters.toColumn(attribute, TenantCryptoRuntime.deterministicCipher()::encrypt);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return TenantConverters.toAttribute(dbData, TenantCryptoRuntime.deterministicCipher()::decrypt);
    }
}
