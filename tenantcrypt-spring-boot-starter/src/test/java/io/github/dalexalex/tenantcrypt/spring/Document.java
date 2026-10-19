package io.github.dalexalex.tenantcrypt.spring;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

/** Test entity exercising both annotations. */
@Entity
@EntityListeners(FingerprintEntityListener.class)
class Document {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    /** Plaintext, so the test can prove the encrypted column differs from it. */
    private String title;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(length = 4096)
    private String text;

    @Convert(converter = EncryptedBytesConverter.class)
    @Column(length = 8192)
    private byte[] original;

    @Fingerprint(of = "text", normalizer = Normalizers.Text.class, minLength = 8)
    @Column(name = "text_fingerprint", length = 128)
    private String textFingerprint;

    @Fingerprint(of = "original")
    @Column(name = "byte_fingerprint", length = 128)
    private String byteFingerprint;

    Long getId() {
        return id;
    }

    String getTenantId() {
        return tenantId;
    }

    void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    String getTitle() {
        return title;
    }

    void setTitle(String title) {
        this.title = title;
    }

    String getText() {
        return text;
    }

    void setText(String text) {
        this.text = text;
    }

    byte[] getOriginal() {
        return original;
    }

    void setOriginal(byte[] original) {
        this.original = original;
    }

    String getTextFingerprint() {
        return textFingerprint;
    }

    String getByteFingerprint() {
        return byteFingerprint;
    }
}
