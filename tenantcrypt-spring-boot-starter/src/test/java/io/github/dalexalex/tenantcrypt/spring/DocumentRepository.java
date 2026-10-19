package io.github.dalexalex.tenantcrypt.spring;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * The point of the fingerprint column: a derived Spring Data query method still works over content
 * that is encrypted at rest.
 */
interface DocumentRepository extends JpaRepository<Document, Long> {

    Optional<Document> findByTenantIdAndTextFingerprint(String tenantId, String textFingerprint);

    Optional<Document> findByTenantIdAndByteFingerprint(String tenantId, String byteFingerprint);
}
