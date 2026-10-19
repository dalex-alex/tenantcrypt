# 0002 — Form and language: a JVM library, written in Java

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

There are two forms this can take: an in-process **library**, or a **sidecar** — a container
exposing HTTP or gRPC, deployed alongside the application, as Vault Transit does. For a component
distributed to many organisations across many languages, the sidecar is often the better form.

These are not two independent decisions followed by a third about language. Choosing the library
form chooses a runtime, and in this case that runtime is the JVM — so the only question left is
which JVM language, and it belongs in the same record.

## Decision

Ship a plain JVM library, written in **Java** (current LTS). Core has no framework dependency; the
Spring Boot integration is a separate optional artefact ([ADR 0008](0008-jpa-persistence-module.md)).

## Rationale

**A sidecar is the wrong architecture for cryptography specifically.** It means sending plaintext
across a network hop to be encrypted: per-field latency, plaintext crossing a process boundary, and
a hard dependency in the request path of every read. Vault Transit works this way, and the reason
people accept the tax is key isolation — plaintext key material never enters the application
process. That is a genuine security property, and giving it up is the real cost of this decision.
It is recorded in the threat model rather than glossed: with an in-process library, anyone with code
execution or a heap dump in the application reads both keys and the plaintext.

**The sidecar's advantage is language-agnostic reach, which this library does not need.** Its
subject is a JVM concern — JPA converters, thread-bound persistence contexts, Tink's Java
primitives — and `implementation("...")` is a thirty-second trial for a JVM developer, where
`docker run` plus a Helm chart is operational work before the first line of code. Reach across
ecosystems is explicitly out of scope ([ADR 0006](0006-scope-boundary.md)).

**Given the JVM, Java rather than Kotlin.** A technical reason, not a preference: **a Java library
is cleanly consumable from Kotlin, Scala and Groovy, while a Kotlin library drags the Kotlin stdlib
into every consumer.** For a library meant to be usable from anywhere on the JVM, that asymmetry
decides it. The code is also small and has no coroutines, no DSLs and little domain modelling — it
is byte arrays, a key-derivation call and a cipher — so Kotlin's expressiveness advantage here is
close to zero.

## Consequences

- **Plaintext key material lives in the application process.** This is the property the sidecar form
  would have bought and this one does not. See `threat-model.md` on a compromised application
  server; no amount of key separation changes it.
- Usable only from the JVM. Accepted; a non-JVM caller needs its own implementation of the same
  construction, which the documented formats make possible.
- Distribution is Maven Central plus GitHub, not container registries.
- Packaging burden stays small: one jar, no images, no multi-arch builds, no chart, no SBOM
  pipeline.
- Records cover the small amount of modelling needed; nothing here wants a richer type system.
- A Kotlin application can depend on the Java library directly with no interop friction.
