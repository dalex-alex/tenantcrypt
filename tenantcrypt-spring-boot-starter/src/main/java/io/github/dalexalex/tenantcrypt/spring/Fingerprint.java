package io.github.dalexalex.tenantcrypt.spring;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Maintains this field as the keyed fingerprint of another field, so an encrypted column stays
 * searchable for equality.
 *
 * <pre>{@code
 * @Entity
 * @EntityListeners(FingerprintEntityListener.class)
 * class Document {
 *     @Convert(converter = EncryptedStringConverter.class)
 *     private String text;
 *
 *     @Fingerprint(of = "text", normalizer = Normalizers.Text.class, minLength = 64)
 *     @Column(length = 128)
 *     private String textFingerprint;
 * }
 *
 * interface DocumentRepository extends JpaRepository<Document, UUID> {
 *     Optional<Document> findByTenantIdAndTextFingerprint(String tenantId, String fingerprint);
 * }
 * }</pre>
 *
 * <p>The annotated field must be a {@code String}. Size the column to the key id length plus 65 —
 * the stored value is the key generation, a colon, then 64 hex characters of HMAC-SHA256
 * ({@code m1:t1:13623a4d…}), and 128 is a sensible default. Index it together with your tenant
 * column, and do not route it through {@link EncryptedStringConverter}: it has to stay plaintext to
 * be indexable, which is the entire point.
 *
 * <p>The generation prefix is what makes a rotation driveable: after rotating a key, every stored
 * fingerprint is stale, and {@code WHERE fp NOT LIKE 'm1:t1:%'} is how you find the rows that still
 * need recomputing. Recomputing means re-reading the source field and saving the entity again —
 * this listener does the rest.
 *
 * <p>Recomputed on insert and on update, before the value is written. It is derived from the source
 * field's in-memory value, so it works whether or not that field is itself encrypted.
 *
 * <p><strong>Scope.</strong> This covers the common case: one fingerprint of one field of the same
 * entity. It does not cover a fingerprint of something that is not a field — the bytes of an upload
 * as they arrived, say, before any entity existed. For those, call {@code TenantFingerprint}
 * directly; the annotation is sugar, not a replacement.
 *
 * <p><strong>Do not fingerprint low-cardinality values.</strong> A deterministic value over a small
 * domain — a status, a country, a boolean — leaks its distribution to anyone holding a database
 * dump even though it is keyed. Fingerprints are for high-entropy content.
 */
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Fingerprint {

    /** The name of the field on this entity whose value is fingerprinted. */
    String of();

    /** How to normalise the value before hashing. Defaults to exact content. */
    Class<? extends FingerprintNormalizer> normalizer() default Normalizers.Exact.class;

    /**
     * Below this many normalised bytes, the fingerprint is left null rather than computed.
     *
     * <p>Defaults to 0, meaning always fingerprint. Raise it for extracted text, where a very short
     * result means the extraction failed and fingerprinting it would collide every failure with
     * every other.
     */
    int minLength() default 0;
}
