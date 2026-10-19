# 0009 — Searchable columns: deterministic encryption by default, fingerprints for the rest

- **Status:** Accepted
- **Date:** 2026-09-18

## Context

AES-GCM is randomised: a fresh IV per call means the same plaintext produces different ciphertext
every time, so **ciphertext can never be compared for equality**. Every feature that needs "have I
seen this before" — de-duplication, idempotency keys, join keys, uniqueness constraints — breaks the
moment the column is encrypted, and teams usually discover this after encrypting it.

Two keyed primitives can restore equality over an encrypted column: a deterministic AEAD (AES-SIV),
which is recoverable, and a keyed MAC (HMAC-SHA256), which is one-way. Both are in scope
([ADR 0006](0006-scope-boundary.md)) because equality is the boundary this library draws. The
question this ADR settles is which one is the default, and what each stored value has to record.

## Decision

**Deterministic encryption is the default searchable primitive**, as `TenantDeterministicCipher`
under envelope version `0x02`. Keyed fingerprints are the specialisation.

Use deterministic encryption unless one of these applies, in which case use a fingerprint:

- **The content is too large to index.** AES-SIV output is plaintext length plus 16 bytes, so a
  document-sized value cannot live in a btree index; a fingerprint is fixed-size whatever the input.
- **The comparison is over a normalised form** — lowercased, whitespace-collapsed — where a
  recoverable value would only recover the normalised text and so be useless as data.
- **The searchable column must be irreversible even to a key holder.** HMAC is one-way; AES-SIV is
  not.

**Both stored forms record the key generation that produced them.** Deterministic ciphertext carries
the same versioned header as randomised ciphertext ([ADR 0004](0004-versioned-envelope.md)). A
fingerprint carries a prefix:

```
m1:t1:13623a4dada1d20f52b2888e78c5543e2a53c0fbce5982f934efc765ff2abd13
```

`TenantFingerprint` exposes `keyIdOf`, `needsRotation`, and `under(tenant, keyId, content)` for
computing a named generation. The MAC itself is unchanged by the prefix — the 64 hex characters
after the colon are what the bare construction produces, which the frozen known-answer vectors
assert.

## Rationale

**Deterministic encryption needs one column instead of two, and the column is readable.** The value
is both the index and the data. A fingerprint is one-way, so it needs a second column beside the
real ciphertext and can never be read back — which is right for a document and wasteful for an email
address.

**Ordinary repository methods keep working, unchanged.** JPA applies an `AttributeConverter` to query
parameters as well as to stored values, so a derived method such as `findByEmail(String)` queries the
encrypted column with no change at the call site. Verified by test. That is a materially better story
than "construct a fingerprint probe and query a second column".

**Recording the generation is what makes rotation driveable, and both forms can do it.** For
deterministic ciphertext the header is itself deterministic, so the value *stays directly
comparable* while still naming its key. For fingerprints the same information fits in a prefix,
because a prefix is deterministic too and the concatenation stays byte-equal for equal inputs — a
fingerprint cannot carry a header to *parse before decrypting*, since there is no decryption, but
that was never what it needed.

Without it, the failure is quiet in the worst direction. A fingerprint's input is plaintext and that
plaintext is retained, so nothing is unrecoverable — but with no generation recorded, **a stale
fingerprint is indistinguishable from an absent document.** No query finds the affected rows, and a
lookup returning nothing looks exactly like a genuine miss. Rotate a key, skip the recompute pass,
and de-duplication silently starts accepting every re-import as new: no exception, no log line, no
way to ask. With the prefix, `WHERE fp NOT LIKE 'm1:t2:%'` selects exactly the rows a recompute still
owes, `needsRotation` is the per-value predicate, and `under` reproduces a retired generation so a
transition can query both sides of a half-finished pass.

**The prefix costs nothing that matters.** Determinism, indexability and the one-way property are
all untouched. Key ids are not secret and already appear in plaintext columns inside ciphertext
envelopes, so recording one here discloses nothing new; what it does reveal is which generation a
row is on, which is the point.

**A cheaper-looking alternative was rejected.** Deriving the fingerprint key from the master key and
tenant id only — leaving it unaffected by tenant data-key rotation — would reduce how often a
recompute is needed. Declined: the recompute pass has to exist either way, so the saving is mostly
theoretical, both keys are expected to rotate rarely, and the change would weaken the two-key
property for this one primitive by making a master-key compromise alone sufficient for confirmation
attacks.

**The cost determinism always has is stated loudly, because it is inherent.** Equal plaintexts are
visibly equal in the column: anyone with the database sees which rows share a value and how often
each value occurs, with no key. Over a low-cardinality domain that frequency distribution usually
identifies the values outright. The converter's javadoc and the threat model both say not to use it
on low-cardinality columns. Ordering, ranges and `LIKE` do not work either — equality only, which is
exactly the boundary ADR 0006 drew.

## What this does not open the door to

The natural next steps from "a derived column that makes encrypted data searchable" are a
fingerprint, then a similarity vector, then a general "derived search column" abstraction. That
gradient is refused here, and **the second step already breaks for a security reason rather than a
scope one.**

A similarity vector has to be computed from plaintext — that is what makes it semantically useful.
Storing embeddings beside encrypted content is therefore a partial plaintext leak, and the published
work on embedding inversion (Morris et al., *Text Embeddings Reveal (Almost) As Much As Text*, 2023)
shows substantial source text can be recovered from embeddings alone. An application that needs
semantic search over sensitive content has to treat the vectors — and usually the chunks beside
them — as disclosed, and say so in its own threat model.

So "encrypted column plus similarity search" is not a feature this library declined for time. It is
one it cannot provide without contradicting its own threat model, and a library that shipped it while
claiming to protect the column would be over-claiming in exactly the way
[ADR 0005](0005-no-assurance-claims.md) forbids.

Equality is the boundary. It is the boundary because it is the only one reachable with a keyed
primitive over ciphertext the server cannot read.

## Consequences

- Three purpose labels exist, and all are part of the stored format: `tenantcrypt-field-v1`,
  `tenantcrypt-deterministic-v1`, `tenantcrypt-fingerprint-v1`.
- AES-SIV needs a 64-byte derived key, so the derivation is per-purpose in length.
- Two version bytes are in use. A column holding a mix of both is a bug, and the error message says
  which cipher wrote the value it found.
- **The fingerprint column must be wider than a bare digest:** `key id length + 65`. With the
  conventional `m1:t1` that is 70 characters; 128 is a sensible default.
- The fingerprint format is a public contract in the same way the envelope is. Changing it later
  needs a deliberate migration, not an edit.
- **A rotation pass has three obligations, all of them expressible:** re-wrap randomised ciphertext,
  re-encrypt deterministic values, and recompute fingerprints from plaintext. The last still
  requires decrypting content — the step an offline re-encryption script is most likely to omit,
  because re-wrapping ciphertext alone looks complete.
