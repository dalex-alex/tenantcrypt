# 0001 — Purpose: a small library, not a platform

- **Status:** Accepted
- **Date:** 2026-09-14

## Decision

This library solves one problem completely: per-tenant envelope encryption for data that still has
to be queryable. It is deliberately small and deliberately finished. It is not a key-management
product and is not a foundation for one.

## Context

Per-tenant field encryption has a narrow technical core — a two-input key derivation, purpose
labels, a stored format that names the key that produced it — surrounded by an unbounded amount of
operational product: KMS adapters, a rotation scheduler, a control plane, revocation workflows,
compliance evidence. The core is worth publishing because it is small enough to read in full and
because the part everyone gets wrong (you encrypt a column and can no longer query it) can be
explained completely. The surrounding product is not, and anything that drifts into it makes the
core harder to audit rather than easier to use.

Google's [Tink](https://developers.google.com/tink) already provides the cryptography: AEAD,
deterministic AEAD, keyset handling, KMS integration. What this library adds is the per-tenant
layer on top — derivation from two independently-held keys, key-use separation, and a stored format
built for rotation. Everything underneath comes from Tink (ADR 0003).

## Consequences

- **Feature requests are answered against the scope boundary, not against demand.** Broad adoption
  is not a goal; a tight, complete, honest library beats a broad one. See
  [ADR 0006](0006-scope-boundary.md).
- No roadmap, no support obligation, no issue SLA. The README says so plainly.
- The library claims no security assurance, and that is a decision rather than an omission. See
  [ADR 0005](0005-no-assurance-claims.md).
- Widening the scope needs a new decision that argues for the crossing, recorded alongside the
  others. It does not happen by accretion.
