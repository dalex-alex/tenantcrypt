package io.github.dalexalex.tenantcrypt.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.dalexalex.tenantcrypt.DecryptionFailedException;
import io.github.dalexalex.tenantcrypt.TenantFingerprint;
import io.github.dalexalex.tenantcrypt.TenantId;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.JpaSystemException;

@TenantCryptoJpaTest
class EncryptedColumnTest {

    private static final TenantId ACME = TenantId.of("acme");
    private static final TenantId GLOBEX = TenantId.of("globex");

    @Autowired private DocumentRepository repository;
    @Autowired private EntityManager entityManager;
    @Autowired private TenantFingerprint fingerprints;

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("an encrypted field round-trips through the database")
    void roundTrip() {
        Long id =
                TenantContext.withTenant(
                        ACME,
                        () -> {
                            Document saved = repository.saveAndFlush(document("the contract text"));
                            entityManager.clear();
                            return saved.getId();
                        });

        TenantContext.withTenant(
                ACME,
                () -> {
                    Document loaded = repository.findById(id).orElseThrow();
                    assertThat(loaded.getText()).isEqualTo("the contract text");
                    assertThat(loaded.getOriginal()).isEqualTo("PDF-BYTES".getBytes(StandardCharsets.UTF_8));
                });
    }

    @Test
    @DisplayName("the stored column really holds a versioned envelope, not the plaintext")
    void storedValueIsCiphertext() {
        Long id =
                TenantContext.withTenant(
                        ACME,
                        () -> repository.saveAndFlush(document("sensitive content")).getId());

        // Read the raw column, bypassing the converter.
        String stored =
                (String)
                        entityManager
                                .createNativeQuery("select text from document where id = :id")
                                .setParameter("id", id)
                                .getSingleResult();

        assertThat(stored).doesNotContain("sensitive content");

        byte[] envelope = Base64.getDecoder().decode(stored);
        assertThat(envelope[0]).as("version byte").isEqualTo((byte) 0x01);
        assertThat(new String(envelope, 2, envelope[1], StandardCharsets.UTF_8)).isEqualTo("m1:t1");
    }

    @Test
    @DisplayName("the binary column holds a raw envelope, not base64 and not the original bytes")
    void storedBytesAreCiphertext() {
        Long id = TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("x")).getId());

        byte[] stored =
                (byte[])
                        entityManager
                                .createNativeQuery("select original from document where id = :id")
                                .setParameter("id", id)
                                .getSingleResult();

        assertThat(stored).isNotEqualTo("PDF-BYTES".getBytes(StandardCharsets.UTF_8));
        assertThat(stored[0]).isEqualTo((byte) 0x01);
    }

    @Test
    @DisplayName("a derived query method over the fingerprint column finds the row — the whole point")
    void fingerprintLookupWorks() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("a unique document body")));

        TenantContext.withTenant(
                ACME,
                () -> {
                    // Normalised the same way the annotation does, then fingerprinted.
                    String lookup =
                            fingerprints.of(ACME, new Normalizers.Text().normalize("A UNIQUE   Document Body"));

                    Optional<Document> found =
                            repository.findByTenantIdAndTextFingerprint(ACME.value(), lookup);

                    assertThat(found).isPresent();
                    assertThat(found.orElseThrow().getText()).isEqualTo("a unique document body");
                });
    }

    @Test
    @DisplayName("the fingerprint column is plaintext hex, and is not itself encrypted")
    void fingerprintColumnIsPlaintext() {
        Long id =
                TenantContext.withTenant(
                        ACME, () -> repository.saveAndFlush(document("a long enough body here")).getId());

        String stored =
                (String)
                        entityManager
                                .createNativeQuery("select text_fingerprint from document where id = :id")
                                .setParameter("id", id)
                                .getSingleResult();

        assertThat(stored).matches("m1:t1:[0-9a-f]{64}");
    }

    @Test
    @DisplayName("minLength leaves the fingerprint null for content too short to be meaningful")
    void shortContentIsNotFingerprinted() {
        Document saved = TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("tiny")));

        assertThat(saved.getTextFingerprint()).isNull();
        // The byte fingerprint has no minimum, so it is still computed.
        assertThat(saved.getByteFingerprint()).matches("m1:t1:[0-9a-f]{64}");
    }

    @Test
    @DisplayName("the fingerprint is recomputed on update")
    void fingerprintFollowsUpdates() {
        Long id =
                TenantContext.withTenant(
                        ACME, () -> repository.saveAndFlush(document("the original body")).getId());

        String before =
                TenantContext.withTenant(ACME, () -> repository.findById(id).orElseThrow().getTextFingerprint());

        TenantContext.withTenant(
                ACME,
                () -> {
                    Document loaded = repository.findById(id).orElseThrow();
                    loaded.setText("a completely different body");
                    repository.saveAndFlush(loaded);
                });

        String after =
                TenantContext.withTenant(ACME, () -> repository.findById(id).orElseThrow().getTextFingerprint());

        assertThat(after).isNotEqualTo(before).matches("m1:t1:[0-9a-f]{64}");
    }

    @Test
    @DisplayName("normalisation means a re-flowed, re-cased copy still matches")
    void normalisationMatchesReExports() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("The Quick  Brown\nFox Jumps")));

        TenantContext.withTenant(
                ACME,
                () -> {
                    String lookup =
                            fingerprints.of(
                                    ACME, new Normalizers.Text().normalize("the quick brown fox jumps"));
                    assertThat(repository.findByTenantIdAndTextFingerprint(ACME.value(), lookup)).isPresent();
                });
    }

    @Test
    @DisplayName("another tenant's fingerprint never matches, even for identical content")
    void fingerprintsAreTenantScoped() {
        TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("identical content here")));

        TenantContext.withTenant(
                GLOBEX,
                () -> {
                    String globexLookup =
                            fingerprints.of(GLOBEX, new Normalizers.Text().normalize("identical content here"));
                    assertThat(repository.findByTenantIdAndTextFingerprint(ACME.value(), globexLookup))
                            .isEmpty();
                });
    }

    @Test
    @DisplayName("another tenant cannot decrypt the row, even reading it directly")
    void crossTenantReadFails() {
        Long id =
                TenantContext.withTenant(
                        ACME,
                        () -> {
                            Long saved = repository.saveAndFlush(document("acme's secret")).getId();
                            entityManager.clear();
                            return saved;
                        });

        TenantContext.set(GLOBEX);

        // Note the wrapping: Hibernate catches the converter's exception and rethrows it as
        // "Error attempting to apply AttributeConverter", which Spring then translates again. The
        // real cause is intact, but callers cannot catch DecryptionFailedException directly.
        Throwable thrown =
                org.assertj.core.api.Assertions.catchThrowable(
                        () -> repository.findById(id).orElseThrow().getText());

        assertThat(thrown).isInstanceOf(JpaSystemException.class);
        assertThat(causeChainOf(thrown)).hasAtLeastOneElementOfType(DecryptionFailedException.class);
    }

    @Test
    @DisplayName("persisting with no tenant in context fails loudly instead of using a default key")
    void missingTenantContextFails() {
        TenantContext.clear();

        assertThatExceptionOfType(MissingTenantContextException.class)
                .isThrownBy(() -> repository.saveAndFlush(document("no tenant set")));
    }

    @Test
    @DisplayName("a null value stays null rather than encrypting to something")
    void nullsArePreserved() {
        Long id =
                TenantContext.withTenant(
                        ACME,
                        () -> {
                            Document doc = new Document();
                            doc.setTenantId(ACME.value());
                            doc.setTitle("no body");
                            Long saved = repository.saveAndFlush(doc).getId();
                            entityManager.clear();
                            return saved;
                        });

        TenantContext.withTenant(
                ACME,
                () -> {
                    Document loaded = repository.findById(id).orElseThrow();
                    assertThat(loaded.getText()).isNull();
                    assertThat(loaded.getOriginal()).isNull();
                    assertThat(loaded.getTextFingerprint()).isNull();
                });
    }

    @Test
    @DisplayName("the plaintext column is untouched, as a control")
    void unannotatedColumnsAreNotEncrypted() {
        Long id = TenantContext.withTenant(ACME, () -> repository.saveAndFlush(document("body")).getId());

        String stored =
                (String)
                        entityManager
                                .createNativeQuery("select title from document where id = :id")
                                .setParameter("id", id)
                                .getSingleResult();

        assertThat(stored).isEqualTo("a title");
    }

    /** Every exception in the chain, so a wrapped cause can be asserted on at any depth. */
    private static java.util.List<Throwable> causeChainOf(Throwable thrown) {
        java.util.List<Throwable> chain = new java.util.ArrayList<>();
        for (Throwable t = thrown; t != null && !chain.contains(t); t = t.getCause()) {
            chain.add(t);
        }
        return chain;
    }

    private static Document document(String text) {
        Document doc = new Document();
        TenantId current = TenantContext.current();
        doc.setTenantId(current == null ? "acme" : current.value());
        doc.setTitle("a title");
        doc.setText(text);
        doc.setOriginal("PDF-BYTES".getBytes(StandardCharsets.UTF_8));
        return doc;
    }
}
