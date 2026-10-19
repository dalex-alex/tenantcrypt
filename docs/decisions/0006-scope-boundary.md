# 0006 — Scope boundary

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

Every item in the out-of-scope list is a plausible next step, and every one turns a small readable
library into an unbounded operational product — the thing [ADR 0001](0001-purpose-and-scope.md)
says this is not. The boundary is written down so that "it's only a small addition" has something
to argue with.

## In scope

Two-input key derivation with purpose labels. AES-256-GCM encrypt/decrypt for strings and bytes.
Deterministic AES-SIV encryption and keyed fingerprints, the two ways to keep a column queryable
([ADR 0009](0009-searchable-columns.md)). The versioned envelope. A
`TenantKeyProvider` interface with one clearly-marked non-production reference implementation.
Rotation *primitives* — decrypt-under-named-key, re-encrypt-under-current-key — and a documented
pattern for driving a pass. One optional Spring Boot artefact mapping encrypted columns through JPA
`@Convert` ([ADR 0008](0008-jpa-persistence-module.md)). A thorough test suite.
Documentation that explains the searchability problem in full.

## Out of scope

- **KMS and secret-store integrations.** One example in the docs, no shipped artefacts. Shipping
  them invites a multi-cloud provider matrix, which is a product.
- **A rotation scheduler, job runner, or migration framework.** Primitives yes, orchestration no.
- **A control plane, admin UI, or key-management service.** A different product with a different
  threat model, an operational surface, and an upgrade story this library deliberately does not
  have.
- **ORM or framework integration beyond the one optional Spring Boot module**, and within that
  module, no encrypted embeddables, collections or associations.
- **Field-level searchable encryption beyond equality.** Range queries and order-preserving
  encryption are a research area with real attack literature. Not here.
- **Compliance evidence packs, questionnaire answers, certification mappings.** This library
  claims no assurance ([ADR 0005](0005-no-assurance-claims.md)); shipping documents that imply
  otherwise would contradict that directly.
- **Multi-language ports.**

## Consequences

- Some users will find the library insufficient for production without writing their own provider
  and their own rotation driver. Intended: the patterns are documented, the plumbing is theirs.
- Feature requests are declined by pointing here. Declining is the default answer.
