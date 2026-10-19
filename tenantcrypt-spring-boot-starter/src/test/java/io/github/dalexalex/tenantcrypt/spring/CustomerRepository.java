package io.github.dalexalex.tenantcrypt.spring;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * The whole point: ordinary derived query methods over a column that is encrypted at rest. No
 * fingerprint column, no manual probe construction.
 */
interface CustomerRepository extends JpaRepository<Customer, Long> {

    Optional<Customer> findByTenantIdAndEmail(String tenantId, String email);

    List<Customer> findByTenantIdAndEmailIn(String tenantId, List<String> emails);

    boolean existsByTenantIdAndEmail(String tenantId, String email);
}
