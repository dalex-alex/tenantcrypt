# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A standalone, framework-free JVM library for per-tenant envelope encryption, published under Apache
2.0. Two modules: `tenantcrypt-core` (Tink and nothing else) and an optional
`tenantcrypt-spring-boot-starter`.

It is deliberately small and deliberately finished (ADR 0001). Resist every suggestion that would
turn it into a product — a key-management service, a control plane, a dashboard, a multi-cloud KMS
matrix. ADR 0006 is the scope boundary, it is deliberately tight, and it lists what is in as well
as what is out. Widening it needs a new ADR that argues for the crossing, not a pull request.

## Documentation conventions

Docs are written for someone deciding whether to use the library or reading the code to judge it.
They explain the design and its limits, not the project's history as a piece of personal work.

- No autobiography, no career or portfolio framing, no "this exists to demonstrate…".
- ADRs are a record of decisions and stay honest about what was reversed, but they argue from
  technical reasons, not from who wrote them.
- Every claim must be verifiable from this repository. Do not cite external codebases, and do not
  describe behaviour of software a reader cannot see.

## Non-negotiables

- **Crypto primitives come from Tink** (ADR 0003). Do not hand-roll AEAD, and do not "simplify" by
  dropping back to raw `javax.crypto`. The failure modes of a hand-written construction — a reused
  IV, a tag compared with `equals`, a mode chosen by string — are silent and survive round-trip
  tests.
- **No assurance claims** (ADR 0005). Every doc says plainly that there has been no third-party
  review. Never soften that, and never add a security claim the threat model does not support.
- **Core has no framework dependency** (ADR 0002). `tenantcrypt-core` depends on Tink and nothing
  else; the starter's main sources compile against the JPA spec and Spring Boot auto-configuration
  only, both `compileOnly`.
- **No legacy-format reading** (ADR 0004). The library reads only the versions it defines — `0x01`
  randomised and `0x02` deterministic — and rejects anything else, including a header-less
  `iv || ciphertext || tag` layout. Do not add a fallback reader; the reasoning against it is
  written down.
- **Purpose labels, version bytes and the key-id scheme are part of the stored format.** Labels are
  `tenantcrypt-field-v1`, `tenantcrypt-deterministic-v1`, `tenantcrypt-fingerprint-v1`; versions are
  `0x01` randomised AES-GCM and `0x02` deterministic AES-SIV; key ids are
  `<masterKeyVersion>:<tenantKeyId>`, with the tenant id also mixed into the HKDF `info`. Changing
  any of them makes existing data unreadable; that needs a new version byte, not an edit. The
  frozen vectors in `KnownAnswerTest` are the tripwire — if they fail, the format changed.
- **Deterministic encryption is the default for searchable columns; fingerprints are the
  specialisation** (ADR 0009). Do not re-promote fingerprints as the headline answer.
- **Every stored value records the key generation that produced it** — ciphertext and deterministic
  ciphertext in the envelope header, fingerprints as a `m1:t1:` prefix (ADR 0009). A rotation pass
  must re-wrap ciphertext, re-encrypt deterministic values, *and* recompute fingerprints from
  plaintext.
- **Similarity search is not a missing feature.** A vector derived from plaintext leaks plaintext,
  so "encrypted column + embeddings" contradicts the threat model. Equality is the boundary and
  ADR 0009 records why.
- **The persistence module targets the JPA spec, not Hibernate** (ADR 0008). Its main sources
  compile against `jakarta.persistence-api` and `spring-boot-autoconfigure` only — a
  provider-specific import is a compile error, and that is deliberate. Do not reintroduce
  `@Encrypted`-style custom annotations; JPA cannot compose `@Convert`, so they would drag Hibernate
  back in to save one annotation.
