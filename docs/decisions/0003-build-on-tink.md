# 0003 — Build on Tink, do not hand-roll primitives

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

The two-input derivation and the fingerprint pattern can be built directly on `javax.crypto` and a
hand-written HKDF in well under a hundred lines, with no third-party dependency at all. The
question is whether that is worth doing.

## Decision

Use [Tink](https://developers.google.com/tink) for AEAD and key handling, with the HKDF-based
two-input derivation layered on top. Do not hand-roll AEAD, and do not revert to raw
`javax.crypto` for convenience.

## Rationale

It is not worth doing. A hand-written AEAD construction is correct until it is not, and the failure
modes — a reused IV, a tag compared with `equals`, a mode selected by string — are quiet and not
caught by round-trip tests. Tink is maintained by a cryptography team, its primitives are reviewed, and its
misuse-resistant API removes most of those choices from this library's hands.

It also supplies more than AEAD: keyset handling, rotation support and `DeterministicAead`
(AES-SIV), the last being the primitive behind deterministic encryption
([ADR 0009](0009-searchable-columns.md)).

The division of labour this sets up is the right one: Tink provides the cryptography, and this
library provides the per-tenant layer — derivation from two keys, key-use separation, and a stored
format built for rotation.

## Consequences

- One external dependency, from a maintained source with a crypto team.
- Some Tink idioms (keysets, key templates) shape the API. Accept them rather than wrapping them
  into something bespoke.
- Where plain HMAC is sufficient — pure equality comparison — use it and document why, rather than
  reaching for AES-SIV because it is available.
