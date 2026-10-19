package io.github.dalexalex.tenantcrypt.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.dalexalex.tenantcrypt.TenantId;
import jakarta.persistence.EntityManager;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@TenantCryptoJpaTest
class DeterministicColumnTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId GLOBEX = TenantId.of("globex");

    @Autowired private CustomerRepository repository;
    @Autowired private EntityManager entityManager;

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("a derived query method finds the row by plaintext, with no fingerprint column")
    void derivedQueryWorksTransparently() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(customer("alice@example.com")));
        entityManager.clear();

        TenantContext.withTenant(
                ACME,
                () -> {
                    Optional<Customer> found =
                            repository.findByTenantIdAndEmail(ACME.value(), "alice@example.com");

                    assertThat(found).isPresent();
                    assertThat(found.orElseThrow().getEmail()).isEqualTo("alice@example.com");
                });
    }

    @Test
    @DisplayName("the column really is ciphertext — version 0x02, not the plaintext")
    void storedValueIsDeterministicCiphertext() {
        Long id =
                TenantContext.withTenant(
                        ACME, () -> repository.saveAndFlush(customer("alice@example.com")).getId());

        String stored =
                (String)
                        entityManager
                                .createNativeQuery("select email from customer where id = :id")
                                .setParameter("id", id)
                                .getSingleResult();

        assertThat(stored).doesNotContain("alice@example.com");
        assertThat(Base64.getDecoder().decode(stored)[0]).isEqualTo((byte) 0x02);
    }

    @Test
    @DisplayName("two rows with the same email store byte-identical values, which is what makes it searchable")
    void equalPlaintextsStoreEqualCiphertext() {
        TenantContext.withTenant(
                ACME,
                () -> {
                    repository.saveAndFlush(customer("shared@example.com"));
                    Customer second = customer("shared@example.com");
                    second.setNotes("a different note");
                    repository.saveAndFlush(second);
                });

        @SuppressWarnings("unchecked")
        List<String> stored =
                entityManager
                        .createNativeQuery("select email from customer order by id")
                        .getResultList();

        assertThat(stored).hasSize(2);
        assertThat(stored.get(0)).isEqualTo(stored.get(1));
    }

    @Test
    @DisplayName("the randomised column on the same entity is NOT comparable, as a control")
    void randomisedColumnStaysIncomparable() {
        TenantContext.withTenant(
                ACME,
                () -> {
                    repository.saveAndFlush(customer("a@example.com"));
                    Customer second = customer("b@example.com");
                    repository.saveAndFlush(second);
                });

        @SuppressWarnings("unchecked")
        List<String> notes =
                entityManager
                        .createNativeQuery("select notes from customer order by id")
                        .getResultList();

        // Same plaintext note on both rows, but randomised encryption makes them differ.
        assertThat(notes).hasSize(2);
        assertThat(notes.get(0)).isNotEqualTo(notes.get(1));
        assertThat(Base64.getDecoder().decode(notes.get(0))[0]).isEqualTo((byte) 0x01);
    }

    @Test
    @DisplayName("an IN query works too, so batch lookups are unaffected")
    void inQueryWorks() {
        TenantContext.withTenant(
                ACME,
                () -> {
                    repository.saveAndFlush(customer("one@example.com"));
                    repository.saveAndFlush(customer("two@example.com"));
                    repository.saveAndFlush(customer("three@example.com"));
                });
        entityManager.clear();

        TenantContext.withTenant(
                ACME,
                () -> {
                    List<Customer> found =
                            repository.findByTenantIdAndEmailIn(
                                    ACME.value(), List.of("one@example.com", "three@example.com"));

                    assertThat(found).hasSize(2);
                    assertThat(found).extracting(Customer::getEmail)
                            .containsExactlyInAnyOrder("one@example.com", "three@example.com");
                });
    }

    @Test
    @DisplayName("exists-by works, which is the de-duplication case")
    void existsWorks() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(customer("dup@example.com")));

        TenantContext.withTenant(
                ACME,
                () -> {
                    assertThat(repository.existsByTenantIdAndEmail(ACME.value(), "dup@example.com")).isTrue();
                    assertThat(repository.existsByTenantIdAndEmail(ACME.value(), "other@example.com")).isFalse();
                });
    }

    @Test
    @DisplayName("another tenant's query never matches, because the value is tenant-scoped")
    void lookupsAreTenantScoped() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(customer("alice@example.com")));
        entityManager.clear();

        TenantContext.withTenant(
                GLOBEX,
                () ->
                        assertThat(repository.findByTenantIdAndEmail(ACME.value(), "alice@example.com"))
                                .as("globex encrypts the probe under its own key, so it cannot match")
                                .isEmpty());
    }

    @Test
    @DisplayName("null stays null")
    void nullsArePreserved() {
        Long id =
                TenantContext.withTenant(
                        ACME,
                        () -> {
                            Customer c = new Customer();
                            c.setTenantId(ACME.value());
                            Long saved = repository.saveAndFlush(c).getId();
                            entityManager.clear();
                            return saved;
                        });

        TenantContext.withTenant(
                ACME,
                () -> assertThat(repository.findById(id).orElseThrow().getEmail()).isNull());
    }

    private static Customer customer(String email) {
        Customer c = new Customer();
        TenantId current = TenantContext.current();
        c.setTenantId(current == null ? "acme" : current.value());
        c.setEmail(email);
        c.setNotes("a note");
        return c;
    }
}
