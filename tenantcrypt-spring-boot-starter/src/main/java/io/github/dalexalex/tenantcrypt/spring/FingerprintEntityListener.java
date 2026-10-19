package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.TenantCryptoException;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Recomputes every {@link Fingerprint} field before the entity is written.
 *
 * <p>Attach it explicitly:
 *
 * <pre>{@code
 * @Entity
 * @EntityListeners(FingerprintEntityListener.class)
 * class Document { ... }
 * }</pre>
 *
 * <p>Explicit rather than registered globally through a Hibernate {@code Integrator}: one visible
 * annotation on the entity, no service-loader machinery, and a reader can see what is modifying
 * their field. The cost is remembering it — so an entity with a {@link Fingerprint} field and no
 * listener would silently never populate it. To make that failure loud instead, the listener
 * validates the annotations it finds and throws on a misconfigured one.
 */
public class FingerprintEntityListener {

    /** Reflection is resolved once per entity class, not once per write. */
    private static final Map<Class<?>, List<Target>> TARGETS = new ConcurrentHashMap<>();

    @PrePersist
    @PreUpdate
    public void applyFingerprints(Object entity) {
        for (Target target : TARGETS.computeIfAbsent(entity.getClass(), FingerprintEntityListener::scan)) {
            target.apply(entity);
        }
    }

    private static List<Target> scan(Class<?> entityClass) {
        List<Target> targets = new ArrayList<>();
        for (Class<?> type = entityClass; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                Fingerprint annotation = field.getAnnotation(Fingerprint.class);
                if (annotation != null) {
                    targets.add(Target.of(type, field, annotation));
                }
            }
        }
        return List.copyOf(targets);
    }

    /** One resolved {@link Fingerprint} field, with the source field and normaliser it needs. */
    private record Target(
            Field target, Field source, FingerprintNormalizer normalizer, int minLength) {

        static Target of(Class<?> owner, Field target, Fingerprint annotation) {
            if (target.getType() != String.class) {
                throw new TenantCryptoException(
                        "@Fingerprint must annotate a String field, but " + describe(target)
                                + " is " + target.getType().getName()
                                + "; a fingerprint is 64 hex characters.");
            }
            Field source = findField(owner, annotation.of(), target);
            target.setAccessible(true);
            source.setAccessible(true);
            return new Target(target, source, instantiate(annotation, target), annotation.minLength());
        }

        private static Field findField(Class<?> owner, String name, Field target) {
            for (Class<?> type = owner; type != null && type != Object.class; type = type.getSuperclass()) {
                try {
                    return type.getDeclaredField(name);
                } catch (NoSuchFieldException ignored) {
                    // keep walking up
                }
            }
            throw new TenantCryptoException(
                    "@Fingerprint(of = \"" + name + "\") on " + describe(target)
                            + " names a field that does not exist on " + owner.getName() + ".");
        }

        private static FingerprintNormalizer instantiate(Fingerprint annotation, Field target) {
            Class<? extends FingerprintNormalizer> type = annotation.normalizer();
            try {
                return type.getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException e) {
                throw new TenantCryptoException(
                        "could not instantiate the normaliser " + type.getName() + " for "
                                + describe(target) + "; it needs a public no-argument constructor.",
                        e);
            }
        }

        void apply(Object entity) {
            Object sourceValue = read(entity);
            byte[] normalized = normalizer.normalize(sourceValue);
            String fingerprint =
                    (normalized == null || normalized.length < minLength)
                            ? null
                            : TenantCryptoRuntime.fingerprints()
                                    .of(TenantContext.currentOrThrow(), normalized);
            write(entity, fingerprint);
        }

        private Object read(Object entity) {
            try {
                return source.get(entity);
            } catch (IllegalAccessException e) {
                throw new TenantCryptoException("could not read " + describe(source), e);
            }
        }

        private void write(Object entity, String fingerprint) {
            try {
                target.set(entity, fingerprint);
            } catch (IllegalAccessException e) {
                throw new TenantCryptoException("could not write " + describe(target), e);
            }
        }

        private static String describe(Field field) {
            return field.getDeclaringClass().getSimpleName() + "." + field.getName();
        }
    }
}
