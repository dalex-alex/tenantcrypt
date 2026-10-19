package io.github.dalexalex.tenantcrypt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * A small synchronised LRU.
 *
 * <p>Derivation is HKDF plus building a Tink primitive, on every single encrypt and decrypt. That
 * is irrelevant at application scale and wasteful in a library, so derived primitives are cached.
 *
 * <p>Bounded, because the natural cache key includes the tenant and an unbounded map keyed by
 * tenant is a memory leak in a system with many tenants. LRU eviction means a busy tenant stays hot
 * and an idle one falls out.
 *
 * <p>Deliberately not Guava or Caffeine: the core has exactly one dependency and it is Tink.
 */
final class BoundedCache<K, V> {

    private final int maxEntries;
    private final Map<K, V> entries;

    BoundedCache(int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("cache must hold at least one entry, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
        this.entries = new LinkedHashMap<>(16, 0.75f, true) {

            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > BoundedCache.this.maxEntries;
            }
        };
    }

    synchronized V get(K key, Function<K, V> compute) {
        V existing = entries.get(key);
        if (existing != null) {
            return existing;
        }
        V computed = compute.apply(key);
        entries.put(key, computed);
        return computed;
    }

    /** Drops every cached primitive, and with it the derived key material each one holds. */
    synchronized void clear() {
        entries.clear();
    }

}
