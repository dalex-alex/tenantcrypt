package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.TenantCipher;
import io.github.dalexalex.tenantcrypt.TenantCryptoException;
import io.github.dalexalex.tenantcrypt.TenantDeterministicCipher;
import io.github.dalexalex.tenantcrypt.TenantFingerprint;
import java.util.Objects;

/**
 * Holds the cipher and fingerprint instances that converters and entity listeners use.
 *
 * <h2>Why this is static, which is a fair thing to object to</h2>
 *
 * Hibernate — not Spring — decides when to instantiate an {@code AttributeConverter} and an entity
 * listener. Spring Boot does register a {@code SpringBeanContainer} that lets Hibernate resolve
 * those as beans, so constructor injection <em>usually</em> works, but it is conditional: it
 * depends on the bean container being installed, and a converter registered through JPA's own
 * {@code @Converter} mechanism is a documented exception to it. A converter that resolves its
 * dependencies through a static holder behaves identically whether Hibernate instantiates it
 * reflectively, Spring's bean container supplies it, or a plain JPA bootstrap with no Spring at all
 * creates it.
 *
 * <p>The trade-off is one process-wide instance. That is already true of the master key, so it costs
 * nothing real — but it does mean two Spring contexts in one JVM (some test setups) share this, and
 * {@link #reset()} exists for that case.
 *
 * <p>{@link TenantCryptoAutoConfiguration} installs this on startup. Nothing else should.
 */
public final class TenantCryptoRuntime {

    private static volatile State state;

    private TenantCryptoRuntime() {}

    /** Installs the runtime. Called by the auto-configuration. */
    public static void install(
            TenantCipher cipher,
            TenantDeterministicCipher deterministicCipher,
            TenantFingerprint fingerprints,
            boolean failSoftReads) {
        Objects.requireNonNull(cipher, "cipher must not be null");
        Objects.requireNonNull(deterministicCipher, "deterministic cipher must not be null");
        Objects.requireNonNull(fingerprints, "fingerprints must not be null");
        state = new State(cipher, deterministicCipher, fingerprints, failSoftReads);
    }

    /** Clears the runtime. Intended for tests. */
    public static void reset() {
        state = null;
    }

    static TenantCipher cipher() {
        return require().cipher();
    }

    static TenantDeterministicCipher deterministicCipher() {
        return require().deterministicCipher();
    }

    static TenantFingerprint fingerprints() {
        return require().fingerprints();
    }

    /**
     * Whether a failed decrypt on read yields null instead of throwing.
     *
     * <p>Off by default, because silently returning null for data that exists is its own kind of
     * bug. Worth turning on for read paths that would rather skip an unreadable row than fail the
     * whole query — which is the behaviour a manual, call-site-by-call-site encryption scheme gives
     * you for free and annotation-driven encryption takes away.
     */
    static boolean failSoftReads() {
        return require().failSoftReads();
    }

    private static State require() {
        State current = state;
        if (current == null) {
            throw new TenantCryptoException(
                    "tenantcrypt is not initialised: no TenantCipher has been installed. If you are "
                            + "using the Spring Boot starter, check that tenantcrypt.master-key is set; "
                            + "outside Spring, call TenantCryptoRuntime.install(...) before persisting "
                            + "any annotated entity.");
        }
        return current;
    }

    private record State(
            TenantCipher cipher,
            TenantDeterministicCipher deterministicCipher,
            TenantFingerprint fingerprints,
            boolean failSoftReads) {}
}
