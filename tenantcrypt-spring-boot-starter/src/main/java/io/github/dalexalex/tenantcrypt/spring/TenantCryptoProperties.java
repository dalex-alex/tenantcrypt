package io.github.dalexalex.tenantcrypt.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the tenantcrypt starter, under the {@code tenantcrypt} prefix. */
@ConfigurationProperties(prefix = "tenantcrypt")
public class TenantCryptoProperties {

    /**
     * The server master key, base64-encoded, decoding to exactly 32 bytes.
     *
     * <p>Half of the two-key model, and the half that is not per-tenant. Supply it from the
     * environment or a secret store. Never commit it, and never put it in the same place as your
     * tenant key material — the whole point is that the two live in different trust domains.
     */
    private String masterKey;

    /** Names the master key generation; it is recorded in every ciphertext. */
    private String masterKeyVersion = "m1";

    /**
     * How many derived key primitives to cache. Size it to the number of tenants active at once.
     */
    private int cacheEntries = 1024;

    /**
     * When true, a value that fails to decrypt reads as null instead of throwing.
     *
     * <p>Off by default. Turning it on trades a loud failure for a silent one, which is usually the
     * wrong trade for data — but it is the right one for a read path that would rather skip an
     * unreadable row than fail the entire query.
     */
    private boolean failSoftReads;

    /**
     * The seed for the built-in reference key provider, used only when no {@code TenantKeyProvider}
     * bean is defined.
     *
     * <p><strong>Not for production.</strong> It derives every tenant key from this one value, which
     * collapses the two-key model into a single secret. See {@code SeedDerivedKeyProvider}. Define
     * your own provider bean backed by a secret store instead.
     */
    private String devSeed;

    /** Names the generation of keys the reference provider derives. */
    private String devSeedKeyId = "t1";

    public String getMasterKey() {
        return masterKey;
    }

    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }

    public String getMasterKeyVersion() {
        return masterKeyVersion;
    }

    public void setMasterKeyVersion(String masterKeyVersion) {
        this.masterKeyVersion = masterKeyVersion;
    }

    public int getCacheEntries() {
        return cacheEntries;
    }

    public void setCacheEntries(int cacheEntries) {
        this.cacheEntries = cacheEntries;
    }

    public boolean isFailSoftReads() {
        return failSoftReads;
    }

    public void setFailSoftReads(boolean failSoftReads) {
        this.failSoftReads = failSoftReads;
    }

    public String getDevSeed() {
        return devSeed;
    }

    public void setDevSeed(String devSeed) {
        this.devSeed = devSeed;
    }

    public String getDevSeedKeyId() {
        return devSeedKeyId;
    }

    public void setDevSeedKeyId(String devSeedKeyId) {
        this.devSeedKeyId = devSeedKeyId;
    }
}
