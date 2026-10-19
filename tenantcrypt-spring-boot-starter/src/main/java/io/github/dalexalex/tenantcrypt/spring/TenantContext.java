package io.github.dalexalex.tenantcrypt.spring;

import io.github.dalexalex.tenantcrypt.TenantId;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * The ambient current tenant, as a thread-local.
 *
 * <p>The core library deliberately takes the tenant as an explicit parameter — that is the right
 * shape for a library. But a JPA {@code AttributeConverter} is handed a value and nothing else: no
 * entity, no column, no tenant. Annotation-driven encryption is therefore only possible with an
 * ambient tenant, which is why this lives in the Spring module and not in the core.
 *
 * <p>Populate it where you already resolve tenancy — typically a servlet filter after
 * authentication — and clear it when the request ends. Work that runs off the request path
 * (schedulers, message consumers, post-commit hooks) must wrap itself in {@link #withTenant}, or
 * persistence of an annotated field will fail with {@link MissingTenantContextException}.
 *
 * <p>Failing loudly is deliberate. The alternative — falling back to some default tenant — would
 * write data under the wrong key, and a wrong key does not fail loudly: it produces ciphertext
 * nobody can read back.
 *
 * <h2>Thread boundaries, and the one sharp edge</h2>
 *
 * A thread-local does not cross a thread hop. Anything that moves work to another thread — an
 * RxJava {@code subscribeOn}/{@code observeOn}, an {@code ExecutorService}, a
 * {@code CompletableFuture} continuation, a Servlet async dispatch — leaves this behind. There are
 * two ways that shows up, and they are not equally bad:
 *
 * <ul>
 *   <li><strong>The tenant is missing.</strong> {@link #currentOrThrow} throws
 *       {@link MissingTenantContextException}. Loud, immediate, no bad data written. This is the
 *       designed outcome and it is fine.
 *   <li><strong>The tenant is stale.</strong> Pooled workers are reused. If anything calls
 *       {@link #set} on a pool thread and does not clear it, the next task on that thread inherits
 *       that tenant. <strong>This is the dangerous one</strong>, and it is asymmetric: reads fail
 *       safe, because the tenant id is bound into the ciphertext's associated data, so decrypting
 *       one tenant's row under another's context throws (and a deterministic lookup simply matches
 *       nothing). <em>Writes do not.</em> You encrypt tenant A's data under tenant B's key: A can no
 *       longer read its own row, and B can — a cross-tenant exposure that is silent at write time.
 * </ul>
 *
 * <p>So: {@link #withTenant} is safe on a pooled thread because it restores the previous value in a
 * {@code finally}. A bare {@link #set} without a matching {@link #clear} is not. Prefer
 * {@code withTenant} everywhere except a request filter that has a guaranteed cleanup hook.
 *
 * <h2>Reactive and async stacks</h2>
 *
 * <p>For anything non-blocking, the better answer is not to use this class at all. The core API
 * takes the tenant as an explicit parameter and has no thread-local anywhere, so it works unchanged
 * under any threading model:
 *
 * <pre>{@code
 * Single.fromCallable(() -> cipher.encrypt(tenant, value))   // tenant captured in the lambda
 *       .subscribeOn(Schedulers.io());
 * }</pre>
 *
 * <p>That is why ambient resolution lives in this optional module and not in the core. It exists
 * because a JPA {@code AttributeConverter} cannot be given a parameter — and JPA is itself
 * thread-bound, since a Hibernate {@code Session} is not thread-safe and the converter runs during
 * flush or hydration on the thread owning the persistence context. For the annotation path, this
 * thread-local's lifetime already matches the lifetime it has to match.
 *
 * <p>If you do need propagation across an RxJava scheduler, wrap the scheduled task once at
 * startup. Note the {@code withTenant} rather than {@code set} — it restores afterwards, so a
 * worker cannot leak a tenant into the next task it runs:
 *
 * <pre>{@code
 * RxJavaPlugins.setScheduleHandler(runnable -> {
 *     TenantId captured = TenantContext.current();        // captured at schedule time
 *     if (captured == null) {
 *         return runnable;
 *     }
 *     return () -> TenantContext.withTenant(captured, runnable);
 * });
 * }</pre>
 *
 * <p>On Reactor or WebFlux there is a supported route instead: Micrometer's context-propagation can
 * bridge a {@code ThreadLocalAccessor} for this value into Reactor's {@code Context}, so it follows
 * the subscription rather than the thread.
 *
 * <p><strong>Do not reach for {@code InheritableThreadLocal}.</strong> It propagates at thread
 * <em>creation</em>, so a pool worker inherits whatever tenant happened to be current when the pool
 * warmed up and then keeps it for the pool's lifetime — strictly worse than the plain thread-local
 * this class uses.
 *
 * <p>Virtual threads need no special handling: each gets its own thread-local, and the per-request
 * thread-per-task model this class assumes is exactly what they restore.
 */
public final class TenantContext {

    private static final ThreadLocal<TenantId> CURRENT = new ThreadLocal<>();

    private TenantContext() {}

    /**
     * Sets the current tenant for this thread, leaving it set.
     *
     * <p>Only safe where cleanup is guaranteed — a request filter with an {@code afterCompletion}
     * hook, or a test. On a pooled thread, an unmatched {@code set} leaks the tenant into the next
     * task that runs there, which can write one tenant's data under another's key. Prefer
     * {@link #withTenant}, which restores the previous value automatically.
     */
    public static void set(TenantId tenant) {
        CURRENT.set(Objects.requireNonNull(tenant, "tenant must not be null"));
    }

    /** The current tenant, or null if none is set. */
    public static TenantId current() {
        return CURRENT.get();
    }

    /**
     * The current tenant.
     *
     * @throws MissingTenantContextException if no tenant is set on this thread
     */
    public static TenantId currentOrThrow() {
        TenantId tenant = CURRENT.get();
        if (tenant == null) {
            throw new MissingTenantContextException(
                    "no tenant in context on thread '" + Thread.currentThread().getName()
                            + "'. Encrypted fields cannot be read or written without one — wrap this "
                            + "work in TenantContext.withTenant(...), or populate the context in your "
                            + "request filter.");
        }
        return tenant;
    }

    /** Removes the current tenant. Call this when a request ends. */
    public static void clear() {
        CURRENT.remove();
    }

    /** Runs {@code work} with {@code tenant} current, restoring the previous value afterwards. */
    public static <T> T withTenant(TenantId tenant, Supplier<T> work) {
        TenantId previous = CURRENT.get();
        set(tenant);
        try {
            return work.get();
        } finally {
            restore(previous);
        }
    }

    /** Runs {@code work} with {@code tenant} current, restoring the previous value afterwards. */
    public static void withTenant(TenantId tenant, Runnable work) {
        withTenant(
                tenant,
                () -> {
                    work.run();
                    return null;
                });
    }

    /** As {@link #withTenant(TenantId, Supplier)}, for work that throws. */
    public static <T> T callWithTenant(TenantId tenant, Callable<T> work) throws Exception {
        TenantId previous = CURRENT.get();
        set(tenant);
        try {
            return work.call();
        } finally {
            restore(previous);
        }
    }

    private static void restore(TenantId previous) {
        if (previous == null) {
            clear();
        } else {
            CURRENT.set(previous);
        }
    }
}
