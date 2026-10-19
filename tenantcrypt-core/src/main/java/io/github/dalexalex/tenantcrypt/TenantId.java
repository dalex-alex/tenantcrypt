package io.github.dalexalex.tenantcrypt;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Identifies a tenant. Opaque to this library: whatever your application calls a tenant — an
 * organisation, a workspace, an account — as a string.
 *
 * <p>The value is bound into the associated data of every ciphertext, so it is part of the stored
 * format. Changing how a tenant's id is spelled makes that tenant's existing data undecryptable.
 * Use a stable identifier such as a UUID, never a mutable one such as a slug or a domain name.
 */
public record TenantId(String value) {

    public TenantId {
        Objects.requireNonNull(value, "tenant id must not be null");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("tenant id must not be empty");
        }
    }

    public static TenantId of(String value) {
        return new TenantId(value);
    }

    byte[] bytes() {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
