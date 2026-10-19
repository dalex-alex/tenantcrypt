package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.MasterKeyRing;
import io.github.dalexalex.tenantcrypt.SeedDerivedKeyProvider;
import io.github.dalexalex.tenantcrypt.TenantCipher;
import io.github.dalexalex.tenantcrypt.TenantDeterministicCipher;
import io.github.dalexalex.tenantcrypt.TenantFingerprint;
import io.github.dalexalex.tenantcrypt.TenantKeyProvider;
import java.util.Base64;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Wires {@link TenantCipher} and {@link TenantFingerprint} from configuration, and installs them
 * into {@link TenantCryptoRuntime} so converters and entity listeners can reach them.
 *
 * <p>Everything here backs off if you define your own bean, and the one bean you really should
 * define yourself is {@link TenantKeyProvider} — the built-in fallback is a development convenience
 * and says so loudly.
 */
@AutoConfiguration
@EnableConfigurationProperties(TenantCryptoProperties.class)
public class TenantCryptoAutoConfiguration {

    /**
     * The master key ring, from {@code tenantcrypt.master-key}.
     *
     * <p>Fails at startup rather than at first encrypt if the key is missing or the wrong size.
     * That is deliberate: a broken key discovered on the first write has already taken the request
     * with it, and a key of the wrong length is never going to start working later.
     */
    @Bean
    @ConditionalOnMissingBean
    public MasterKeyRing tenantcryptMasterKeyRing(TenantCryptoProperties properties) {
        String configured = properties.getMasterKey();
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException(
                    "tenantcrypt.master-key is not set. It must be 32 bytes, base64-encoded — "
                            + "generate one with: head -c 32 /dev/urandom | base64");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(configured.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("tenantcrypt.master-key is not valid base64", e);
        }
        if (key.length != MasterKeyRing.KEY_LENGTH) {
            throw new IllegalStateException(
                    "tenantcrypt.master-key must decode to " + MasterKeyRing.KEY_LENGTH
                            + " bytes, but decoded to " + key.length);
        }
        return MasterKeyRing.of(properties.getMasterKeyVersion(), key);
    }

    /**
     * A development-only key provider, used only when the application defines none.
     *
     * <p>Requires {@code tenantcrypt.dev-seed} to be set explicitly, so that no application ever
     * gets a working-but-insecure key source by accident.
     */
    @Bean
    @ConditionalOnMissingBean(TenantKeyProvider.class)
    public TenantKeyProvider tenantcryptReferenceKeyProvider(TenantCryptoProperties properties) {
        String seed = properties.getDevSeed();
        if (seed == null || seed.isBlank()) {
            throw new IllegalStateException(
                    "No TenantKeyProvider bean is defined and tenantcrypt.dev-seed is not set. "
                            + "In production, define a TenantKeyProvider backed by a secret store "
                            + "holding one random key per tenant. For local development only, set "
                            + "tenantcrypt.dev-seed to at least "
                            + SeedDerivedKeyProvider.MIN_SEED_LENGTH
                            + " characters — it derives every tenant key from that one value, which "
                            + "is not the security model this library advertises.");
        }
        return SeedDerivedKeyProvider.of(seed, properties.getDevSeedKeyId());
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantCipher tenantCipher(
            MasterKeyRing masterKeys, TenantKeyProvider keyProvider, TenantCryptoProperties properties) {
        return TenantCipher.builder()
                .masterKeys(masterKeys)
                .keyProvider(keyProvider)
                .cacheEntries(properties.getCacheEntries())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantDeterministicCipher tenantDeterministicCipher(
            MasterKeyRing masterKeys, TenantKeyProvider keyProvider, TenantCryptoProperties properties) {
        return TenantDeterministicCipher.builder()
                .masterKeys(masterKeys)
                .keyProvider(keyProvider)
                .cacheEntries(properties.getCacheEntries())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantFingerprint tenantFingerprint(
            MasterKeyRing masterKeys, TenantKeyProvider keyProvider, TenantCryptoProperties properties) {
        return TenantFingerprint.builder()
                .masterKeys(masterKeys)
                .keyProvider(keyProvider)
                .cacheEntries(properties.getCacheEntries())
                .build();
    }

    /**
     * Installs the runtime that converters and entity listeners read from.
     *
     * <p>An {@link InitializingBean} rather than a listener on a later lifecycle event, because
     * Hibernate may persist entities during startup and the runtime has to be in place first.
     */
    @Bean
    public InitializingBean tenantcryptRuntimeInstaller(
            TenantCipher cipher,
            TenantDeterministicCipher deterministicCipher,
            TenantFingerprint fingerprints,
            TenantCryptoProperties properties) {
        return () ->
                TenantCryptoRuntime.install(
                        cipher, deterministicCipher, fingerprints, properties.isFailSoftReads());
    }
}
