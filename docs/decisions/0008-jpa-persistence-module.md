# 0008 — Optional JPA persistence module, mapped with `@Convert`

- **Status:** Accepted
- **Date:** 2026-09-18

## Context

The core API takes the tenant as an explicit parameter, which means an application using it calls
`encrypt(tenant, value)` at every write site and `decrypt(tenant, value)` at every read site. For a
single encrypted field that is fine. For a dozen fields across a handful of entities it is dozens of
call sites that all say the same thing, and each one is a place to forget — and forgetting means
writing plaintext into a column everything else treats as encrypted, with no error at the time it
happens.

A JPA `AttributeConverter` is the natural place to put encryption instead: it runs on every read and
write of the field by construction. But a converter receives a value and nothing else — no entity,
no column, no tenant — so converter-based encryption is only possible with an *ambient* tenant,
which is exactly what the core deliberately refuses to have.

That makes this a scope question as well as a design one. [ADR 0006](0006-scope-boundary.md) keeps
ORM and framework integration out of scope except for one optional Spring module; this is that
module, and nothing beyond it.

## Decision

Ship `tenantcrypt-spring-boot-starter` as a second, optional artefact containing:

- `EncryptedStringConverter`, `EncryptedBytesConverter` and `DeterministicStringConverter`, mapped
  with the **JPA-standard `@Convert`**:

  ```java
  @Convert(converter = DeterministicStringConverter.class)
  private String email;
  ```

- `@Fingerprint(of = "...")` plus `FingerprintEntityListener`, maintaining a keyed-fingerprint
  column on insert and update, with a pluggable normaliser and a minimum-length policy.
- `TenantContext`, the thread-local the core deliberately refuses to have.
- Auto-configuration binding the master key and building the ciphers.

The module's main sources compile against `jakarta.persistence-api` and `spring-boot-autoconfigure`
**only** — not Hibernate, and not even `spring-data-jpa`.

## Rationale

**Removing the boilerplate is most of the value.** The problem this library exists to solve is
"encrypt a column and you can no longer query it". A declarative mapping that encrypts a column
*and keeps a derived query method working over it* solves it in about eight lines of entity code,
with no call site left to forget. "Call this method at every read and write site" solves it only as
long as nobody forgets.

**The ambient-context problem belongs here and nowhere else.** The core stays explicit and therefore
usable under any threading model; the thread-local lives in this module because a converter cannot
be handed a parameter, and JPA is already thread-bound — a persistence context is not thread-safe,
and the converter runs on the thread that owns it. The split is demonstrated rather than asserted.

**Mapping with `@Convert` rather than a custom `@Encrypted` annotation.** A shorter, library-specific
annotation is the obvious API, and it was rejected: JPA has no mechanism for composing `@Convert`
into another annotation, so a custom one requires a provider SPI — Hibernate's `AttributeBinder`,
plus `ConverterDescriptor.TYPE_NAME_PREFIX` and `BasicValue.setTypeName`. What that buys is about
forty characters per field and type dispatch from the field's declared type. What it costs:

- **Portability.** A provider SPI ties the module to Hibernate for the sake of an abbreviation.
- **A silent plaintext failure mode**, which is the decisive one. An unrecognised annotation on a
  non-Hibernate provider is simply ignored: nothing reads it, no error is raised, and the field is
  stored **in plaintext**. Unlikely in practice, since a Spring Boot starter ships Hibernate by
  default — but silent plaintext is the worst outcome this library has, and `@Convert` cannot fail
  that way.
- **Visibility.** In a crypto library, *which* converter runs — randomised or deterministic — is
  information worth seeing at the field rather than inferring from its type.

Startup validation is not a counter-argument: a mismatched converter on a plain `@Convert` already
fails at startup, because the specification requires it.

**The rule the core already follows extends one layer out.** [ADR 0002](0002-form-jvm-library.md)
makes "core has no framework dependency" a headline property; targeting the JPA *specification*
rather than one implementation is the same argument applied to the integration. And it is enforced
rather than merely observed — narrowing the compile dependency to the spec means a provider-specific
import is a compile error, which is the difference between *we do not use Hibernate* and *we
cannot*.

`@Fingerprint` and `FingerprintEntityListener` are the exception that proves the rule: entity
listeners and `@PrePersist`/`@PreUpdate` are specification features, so this custom annotation does
real work *through* the spec rather than around it.

## What is still out of scope

Everything else in ADR 0006 applies here too: no rotation scheduler or job runner, no KMS
artefacts, no control plane, no searchable encryption beyond equality, no compliance packs, no
multi-language ports. And within this module: no support for encrypted embeddables, collections or
associations, and no global listener registration through a provider extension —
`@EntityListeners` stays explicit so a reader can see what modifies their field.

## Consequences

- Two published artefacts instead of one. The core keeps exactly one dependency, Tink; Spring and
  the JPA API are `compileOnly` here and never reach a core-only consumer.
- Portable across JPA providers, not only Hibernate.
- Callers write one annotation per encrypted field, naming the converter explicitly.
- Two behaviours had to be documented rather than fixed, because both are inherent to converting
  inside the ORM:
  - **Associated data cannot bind the column**, since a converter does not know where its value is
    stored. Recorded in [ADR 0004](0004-versioned-envelope.md) and the threat model.
  - **Decryption failures do not arrive as themselves.** A provider rethrows the converter's
    exception and Spring translates it again, so callers see a `JpaSystemException` with
    `DecryptionFailedException` in its cause chain, and a row that cannot be decrypted fails every
    query loading that entity rather than only the code that wanted the field.
    `tenantcrypt.fail-soft-reads` exists for read paths that would rather skip such a row. This is
    provider behaviour, and it is documented on `EncryptedStringConverter`.
- The static `TenantCryptoRuntime` holder is a deliberate choice, not an oversight: the provider owns
  converter and listener instantiation, and a static holder behaves identically whether the provider
  instantiates reflectively, Spring's bean container supplies the instance, or a plain JPA bootstrap
  with no Spring at all creates it.
