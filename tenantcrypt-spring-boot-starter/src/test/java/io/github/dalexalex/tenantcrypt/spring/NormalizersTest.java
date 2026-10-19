package io.github.dalexalex.tenantcrypt.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.dalexalex.tenantcrypt.TenantCryptoException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class NormalizersTest {

    private final Normalizers.Exact exact = new Normalizers.Exact();
    private final Normalizers.Text text = new Normalizers.Text();

    @Test
    @DisplayName("determinism over byte[]: two equal arrays normalise identically")
    void byteArraysAreValueBased() {
        byte[] first = "PDF-BYTES".getBytes(StandardCharsets.UTF_8);
        byte[] second = "PDF-BYTES".getBytes(StandardCharsets.UTF_8);

        assertThat(exact.normalize(first)).isEqualTo(exact.normalize(second));
        assertThat(text.normalize(first)).isEqualTo(text.normalize(second));
    }

    @Test
    @DisplayName("a byte[] is never normalised via toString, which would be its identity hash")
    void byteArraysAreNotIdentityHashed() {
        String normalized = new String(text.normalize("abc".getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        assertThat(normalized).isEqualTo("abc").doesNotContain("[B@").doesNotContain("[b@");
    }

    @Test
    @DisplayName("text arriving as bytes or as a String normalises the same way")
    void bytesAndStringsAgree() {
        assertThat(text.normalize("The  Quick\nBrown Fox"))
                .isEqualTo(text.normalize("The  Quick\nBrown Fox".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("Text lowercases, collapses whitespace runs and trims")
    void textNormalisation() {
        assertThat(new String(text.normalize("  The   Quick\n\tBrown  FOX  "), StandardCharsets.UTF_8))
                .isEqualTo("the quick brown fox");
    }

    @Test
    @DisplayName("a type with no value-based toString is refused, not silently identity-hashed")
    void unsupportedTypesAreRefused() {
        Object noValueSemantics = new Object();

        assertThatExceptionOfType(TenantCryptoException.class)
                .isThrownBy(() -> exact.normalize(noValueSemantics))
                .withMessageContaining("stable, value-based");
        assertThatExceptionOfType(TenantCryptoException.class)
                .isThrownBy(() -> text.normalize(noValueSemantics));
    }

    @Test
    @DisplayName("other array types are refused too — char[] has the same identity-hash problem")
    void otherArrayTypesAreRefused() {
        assertThatExceptionOfType(TenantCryptoException.class)
                .isThrownBy(() -> exact.normalize(new char[] {'a', 'b'}));
    }

    @Test
    @DisplayName("even a safe-looking type is refused, so the rule is one a reader can predict")
    void valueTypesStillNeedAnExplicitNormalizer() {
        assertThatExceptionOfType(TenantCryptoException.class)
                .isThrownBy(() -> exact.normalize(UUID.randomUUID()))
                .withMessageContaining("FingerprintNormalizer");
    }

    @Test
    @DisplayName("null in, null out — the fingerprint column is left null")
    void nullsPassThrough() {
        assertThat(exact.normalize(null)).isNull();
        assertThat(text.normalize(null)).isNull();
    }
}
