package io.github.dalexalex.tenantcrypt.spring;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

/** Test entity for the deterministic, searchable mapping. */
@Entity
class Customer {

    @Id @GeneratedValue private Long id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    /** Searchable and recoverable: one column does both jobs. */
    @Convert(converter = DeterministicStringConverter.class)
    @Column(length = 512)
    private String email;

    /** Not searched, so randomised — no equality leak. */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(length = 512)
    private String notes;

    Long getId() {
        return id;
    }

    String getTenantId() {
        return tenantId;
    }

    void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    String getEmail() {
        return email;
    }

    void setEmail(String email) {
        this.email = email;
    }

    String getNotes() {
        return notes;
    }

    void setNotes(String notes) {
        this.notes = notes;
    }
}
