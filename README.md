# tenantcrypt

Per-tenant envelope encryption for the JVM, for columns that still have to be **queryable**: a
two-input key derivation (server master key + per-tenant data key) feeding AES-256-GCM for ordinary
fields, AES-SIV where a field must stay searchable, and keyed HMAC fingerprints for content too
large to index.

Primitives come from [Tink](https://developers.google.com/tink); nothing here is hand-rolled.

## No security assurance is claimed

**No third-party cryptographic review. No audit. One author.** Read
[`docs/threat-model.md`](docs/threat-model.md) — including the "what this does not protect against"
half — before using this for anything real. Saying this plainly is a deliberate design decision
([ADR 0005](docs/decisions/0005-no-assurance-claims.md)), not boilerplate.

---

## The problem nobody warns you about

You encrypt a column. Then you discover you can no longer query it.

AES-GCM is randomised: a fresh IV per call means the same plaintext produces different ciphertext
every time. That is exactly what you want — and it means **ciphertext can never be compared for
equality**. Every feature that needs "have I seen this before" breaks at once:

```sql
-- All of these are now dead:
SELECT * FROM documents WHERE content = ?;        -- never matches
SELECT * FROM documents WHERE content LIKE ?;     -- meaningless
CREATE UNIQUE INDEX ON documents (content);       -- enforces nothing
```

De-duplication, idempotency keys, join keys, uniqueness constraints. Teams usually find this out
*after* the column is encrypted and the feature is in production.

## The fix, and which one to use

There are two ways to keep a column queryable. Use the first unless you have a reason not to.

### 1. Deterministic encryption — the default

AES-SIV, via `DeterministicStringConverter`. The same plaintext always encrypts to the same bytes for a tenant, so
the column compares, joins and indexes normally — and the value is **recoverable**, so one column is
both the index and the data:

```java
@Entity
class Customer {
    @Convert(converter = DeterministicStringConverter.class)
    private String email;        // encrypted at rest, still searchable

    @Convert(converter = EncryptedStringConverter.class)
    private String notes;        // randomised: not searchable, no equality leak
}

interface CustomerRepository extends JpaRepository<Customer, Long> {
    // Works unchanged. Scope by tenant as you would for any other column.
    Optional<Customer> findByTenantIdAndEmail(String tenantId, String email);
}
```

That repository method needs no special handling: JPA applies the converter to query parameters as
well as to stored values, so the probe is encrypted the same way the column was.

**What determinism costs.** Equal plaintexts are *visibly equal* in the column. Anyone with the
database can see which rows share a value and how often each distinct value occurs, without any key.
Over a low-cardinality domain — a status, a country, a boolean — that frequency distribution usually
identifies the values outright, so **do not use it there**. It suits high-cardinality identifiers:
an email address, an account number, a national ID. Equality only — no ordering, no ranges, no
`LIKE`.

### 2. Keyed fingerprints — the specialisation

Derive a separate key under a different purpose label and MAC the content with it:

```
k_fp        = HKDF-SHA256( ikm  = master_key || tenant_key,
                           salt = none,
                           info = "tenantcrypt-fingerprint-v1" || "/" || tenant_id )

fingerprint = "<keyGeneration>:" || hex( HMAC-SHA256( k_fp, content ) )

  m1:t1:13623a4dada1d20f52b2888e78c5543e2a53c0fbce5982f934efc765ff2abd13
```

Size the column to the key id length plus 65; 128 is a sensible default.

Reach for this instead of deterministic encryption when:

- **The content is too large to index.** A fingerprint is a fixed 70 characters whatever the input
  size;
  AES-SIV output is plaintext length plus 16 bytes, so a document cannot go in a btree index.
- **You compare a normalised form** — lowercased, whitespace-collapsed, so a re-exported document
  still matches itself. A recoverable value would only recover the normalised text, which is useless
  as data.
- **You want the index to be irreversible even to a key holder.** HMAC is one-way: someone with the
  key can confirm a guess but cannot recover the content. AES-SIV hands them the plaintext.

It is an HMAC and not a bare SHA-256 because the value sits in a plaintext indexed column: an
unkeyed digest is a confirmation oracle for any candidate file someone already holds. It is
tenant-scoped because the tenant id is mixed into the key derivation — so identical content under two
tenants gives different fingerprints *even if your key provider mistakenly hands both tenants the
same key material*. Isolation is a property of the library, not a promise the provider has to keep.

**Rotation.** The key is derived from both keys, so rotating either changes every fingerprint. That
does not lose anything — the input is plaintext and is still there — but a stored value computed
under a retired key stops matching, so a rotation pass has to **recompute** fingerprints from the
plaintext rather than only re-wrap ciphertext.

The generation prefix is what makes that pass driveable. Say you have rotated from `m1:t1` to
`m1:t2`: `WHERE fp NOT LIKE 'm1:t2:%'` selects exactly the rows still owed a recompute,
`needsRotation` is the per-value predicate, and `under(tenant, keyId, content)` reproduces a retired
generation so a transitional query can match rows on either side of the pass:

```java
repository.findByFingerprintIn(List.of(
        fingerprints.of(tenant, content),                   // m1:t2, the current generation
        fingerprints.under(tenant, "m1:t1", content)));     // m1:t1, not yet recomputed
```

### What neither of these does

Similarity search. A vector has to be computed from plaintext, so storing embeddings beside
encrypted content leaks it — there is published work recovering substantial source text from
embeddings alone. That is not a feature left out for time; it is one this library cannot provide
without contradicting its own threat model. Equality is the boundary, and
[ADR 0009](docs/decisions/0009-searchable-columns.md) explains why it is the only one
reachable.

---

## Quick start

```java
MasterKeyRing masterKeys = MasterKeyRing.of("m1", masterKeyBytes);   // 32 bytes, from your secret store
TenantKeyProvider keys = myVaultBackedProvider();                    // one random key per tenant

TenantId tenant = TenantId.of("acme");

// Searchable and recoverable — the default for a field you query.
TenantDeterministicCipher searchable = TenantDeterministicCipher.builder()
        .masterKeys(masterKeys).keyProvider(keys).build();

String email = searchable.encrypt(tenant, "alice@example.com");  // same input, same output
assert email.equals(searchable.encrypt(tenant, "alice@example.com"));
String recovered = searchable.decrypt(tenant, email);

// Randomised — for anything you do not query.
TenantCipher cipher = TenantCipher.builder()
        .masterKeys(masterKeys).keyProvider(keys).build();

String stored = cipher.encrypt(tenant, "the contract text");
String back   = cipher.decrypt(tenant, stored);

// Keyed fingerprint — for content too large to index.
TenantFingerprint fingerprints = TenantFingerprint.builder()
        .masterKeys(masterKeys).keyProvider(keys).build();

String lookup = fingerprints.of(tenant, documentBytes);          // 64 hex chars
```

The tenant is always an explicit parameter. Resolving it from ambient state is right for an
application and wrong for a library — the Spring module below supplies that if you want it.

## The two-key model

```
derived_key = HKDF-SHA256( ikm  = server_master_key || tenant_data_key,
                           salt = none,
                           info = purpose label )
```

- **Server master key** — one per deployment, 32 bytes, from the environment or a secret store.
  Never in the database.
- **Tenant data key** — one per tenant, 32 bytes, from a secret store.
- **Neither key alone decrypts anything.** A database leak gets you nothing; a leak of *one* secret
  store gets you nothing. That property only holds if the two genuinely live in different trust
  domains — putting both in the same `.env` preserves only the database-leak protection.
- **Purpose labels** separate key uses through HKDF's `info`. The cheapest correctness property in
  the design, and the one most often skipped.

## The envelope

```
0x01  version[1] || key_id_len[1] || key_id[n] || iv[12] || ciphertext || tag[16]   randomised, AES-GCM
0x02  version[1] || key_id_len[1] || key_id[n] || siv_tag[16] || ciphertext         deterministic, AES-SIV
```

with `version || key_id || tenant_id` bound as associated data in both cases. Each cipher rejects the
other's version by name, so a column holding a mix is reported rather than failing an authentication
tag for reasons nobody can diagnose.

This header is the part most hand-written field encryption leaves out. Without a key id there is no
way to tell **which key encrypted a given row** — and therefore no rotation, no re-encryption, no
algorithm migration, and no way to run two keys during a transition. It costs two bytes plus the key
id. It cannot be added retroactively.

Key ids are `<masterKeyVersion>:<tenantKeyId>`, so either half can rotate independently.

## Rotation

Primitives, not a scheduler:

```java
if (cipher.needsRotation(tenant, stored)) {
    stored = cipher.rewrapString(tenant, stored);   // decrypt under the old key, re-encrypt under current
}
```

Driving a pass over a table — batching, checkpointing, resuming after failure — is yours to write.
That is a deliberate boundary ([ADR 0006](docs/decisions/0006-scope-boundary.md)).

Deterministic values rotate the same way, and because they carry their key id you can find the rows
that still need it (`needsRotation`) and query both generations while the pass runs.

> **One trap worth stating loudly.** Fingerprints are derived from the master key too, so rotating
> it **invalidates every stored fingerprint**. Recomputing one needs the *plaintext*, which means a
> rotation pass has to decrypt content again, not just re-wrap ciphertext. A pass that re-wraps
> ciphertext and skips fingerprints leaves every equality lookup broken — so treat recomputing them
> as a third obligation alongside the two above, and use the generation prefix
> (`needsRotation`, `WHERE fp NOT LIKE '<current>:%'`) to find the rows that still owe it.

## Optional: Spring Boot, with annotations

A second artefact, `tenantcrypt-spring-boot-starter`, for the ORM case. It targets the **JPA
specification** — its main sources compile against `jakarta.persistence` and Spring Boot's
auto-configuration only, with no Hibernate and no `spring-data-jpa`, so it works on any JPA
provider.

For a searchable field, the deterministic converter is all you need (see above). For large content,
pair the randomised converter with a `@Fingerprint` column the listener maintains:

```java
@Entity
@EntityListeners(FingerprintEntityListener.class)
class Document {

    @Convert(converter = EncryptedStringConverter.class)
    private String text;                    // encrypted at rest

    @Fingerprint(of = "text", normalizer = Normalizers.Text.class, minLength = 64)
    @Column(length = 128)                   // "m1:t1:" + 64 hex = 70; 128 leaves room
    private String textFingerprint;         // maintained automatically, stays plaintext and indexed
}

interface DocumentRepository extends JpaRepository<Document, Long> {
    // Still works, over content that is encrypted in the database.
    Optional<Document> findByTenantIdAndTextFingerprint(String tenantId, String fingerprint);
}
```

Work off the request path wraps itself in the tenant context:

```java
TenantContext.withTenant(tenant, () -> repository.save(document));
```

### Threading

`TenantContext` is a thread-local, so it does not survive a thread hop — an RxJava
`subscribeOn`/`observeOn`, an executor submit, a `CompletableFuture` continuation. Two outcomes,
and they are not equally bad:

- **Tenant missing** → `MissingTenantContextException`. Loud, no bad data. Fine.
- **Tenant stale** → a pooled worker reused after a bare `set()` that was never cleared inherits the
  previous tenant. Reads fail safe (the tenant is bound into the ciphertext's associated data, so a
  wrong-tenant decrypt throws and a deterministic lookup matches nothing), but **writes do not**: you
  encrypt tenant A's data under B's key, A cannot read its own row, and B can.

So use `withTenant(...)`, which restores the previous value in a `finally`. Reserve bare `set()` for
a request filter with a guaranteed cleanup hook.

**On a reactive stack, skip this class.** The core API takes the tenant as a parameter and has no
thread-local at all, so it works under any threading model:

```java
Single.fromCallable(() -> cipher.encrypt(tenant, value))
      .subscribeOn(Schedulers.io());
```

That is why ambient resolution lives only in this optional module: it exists because a JPA converter
cannot be handed a parameter, and JPA is already thread-bound — a Hibernate `Session` is not
thread-safe, and the converter runs on the thread owning the persistence context. If you do need
propagation across RxJava schedulers, wrap scheduled tasks once via
`RxJavaPlugins.setScheduleHandler` using `withTenant` (not `set`); on Reactor, Micrometer's
context-propagation can bridge it into Reactor's `Context`. Don't use `InheritableThreadLocal` —
it propagates at thread creation, so a pool worker keeps whatever was current at warm-up.

Two things to know before adopting the converters:

1. **Decryption failures do not arrive as themselves.** Hibernate wraps converter exceptions, so you
   get a `JpaSystemException` with `DecryptionFailedException` in its cause chain, and a row that
   cannot be decrypted fails *every* query loading that entity. `tenantcrypt.fail-soft-reads=true`
   makes such a value read as null instead.
2. **Associated data cannot bind the column**, because a converter never learns where its value is
   stored. Within one tenant, a ciphertext can still be relocated between columns of the same kind.

## Installing

**Not yet published to Maven Central.** The coordinates below are what a release will use; until
then, build from source with `./gradlew publishToMavenLocal` and add `mavenLocal()` to your
repositories.

```kotlin
implementation("io.github.dalex-alex:tenantcrypt-core:0.1.0-SNAPSHOT")
implementation("io.github.dalex-alex:tenantcrypt-spring-boot-starter:0.1.0-SNAPSHOT")  // optional
```

Java 21 or newer. The core depends on Tink and nothing else.

## Scope

A small library that does one thing: derive per-tenant keys, and store values under them in a format
that can be rotated ([ADR 0001](docs/decisions/0001-purpose-and-scope.md)). It is not a
key-management platform and is not on the way to becoming one. There is no roadmap, no support
obligation and no issue SLA; feature requests are answered against
[ADR 0006](docs/decisions/0006-scope-boundary.md), and declining is the default answer.

Not included, on purpose: KMS integrations, a rotation scheduler, a control plane or key-management
service, searchable encryption beyond equality, compliance evidence packs, multi-language ports.

## Documentation

| File | What's in it |
|---|---|
| [`docs/design.md`](docs/design.md) | The two-key model, the stored formats, and both searchable primitives |
| [`docs/threat-model.md`](docs/threat-model.md) | Protections, non-protections, and the honest limits |
| [`docs/decisions/`](docs/decisions/) | ADRs — what was decided, and why |

## Licence

[Apache 2.0](LICENSE).
