# 0004 — Versioned ciphertext envelope

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

The layout that application-level field encryption usually stores is whatever the AEAD emitted:

```
iv[12] || ciphertext || tag[16]
```

No key id, no key version, no algorithm identifier. Every value in the database is therefore
indistinguishable from every other, and **there is no way to determine which key encrypted a given
value.**

That single omission is what makes rotation impossible rather than merely tedious: with no way to
identify a value's key, changing a key orphans every row already written under the old one, and
there is no query that finds them. The missing header is the cause, not the symptom.

## Decision

**1. Every stored value carries a header naming the key that produced it.**

```
0x01  version[1] || key_id_len[1] || key_id[n] || iv[12] || ciphertext || tag[16]   AES-GCM
0x02  version[1] || key_id_len[1] || key_id[n] || siv_tag[16] || ciphertext         AES-SIV
```

Version `0x02` is the deterministic format ([ADR 0009](0009-searchable-columns.md)); the version
byte is what made adding it a decision rather than a migration.

**2. The header and the tenant id are bound as AEAD associated data.**

```
aad = version || key_id || tenant_id
```

**3. The key id is `<masterKeyVersion>:<tenantKeyId>`.** One opaque, length-prefixed string as far
as the format is concerned, composed of both halves of the derivation because either can rotate
independently. Neither half may contain `:`. Capped at 255 bytes by the single-byte length prefix.

**4. The tenant id is bound into the key derivation, not only the associated data.**

```
info = <purpose label> || "/" || tenant_id
```

**5. There is no legacy-format reading.** The library reads only the versions it defines and nothing
else. A value that is not a well-formed envelope of a known version is rejected with
`MalformedEnvelopeException` rather than guessed at.

## Rationale

**The header is cheap now and impossible later.** Without it there is no rotation, no re-encryption,
no algorithm migration, and no way to run two keys during a transition. With it, all of those become
ordinary. This is the one design choice here that cannot be revisited: a header can be added to a new
deployment for two bytes, and cannot be added to data already written without decrypting all of it
under a key nothing records.

**Associated data is free and closes a real gap.** Tink's `Aead.encrypt` takes associated data as a
parameter, so this costs nothing to add. It buys two properties: the header becomes tamper-evident,
so the version and key id cannot be edited undetected; and a ciphertext lifted from one tenant's row
and dropped into another's fails to decrypt instead of silently succeeding. Without it, key
isolation alone does not prevent relocation, because two tenants can legitimately share a key id.

What it does *not* bind is the column or the row, because a stored value does not know where it is
stored. Within one tenant, a ciphertext can still be moved between two columns holding the same kind
of value. That limit is recorded in the threat model rather than papered over.

**Binding the tenant into the derivation closes a gap associated data cannot cover.** Associated
data protects *ciphertext*: a value moved between tenants fails to decrypt. But a keyed fingerprint
has no associated data — it cannot, because it has to be byte-equal to the value already stored for
a lookup to match. With the purpose label alone as `info`, a fingerprint's tenant-scoping would come
entirely from the tenant key material being different per tenant, which makes it a property of the
*key provider* rather than of this library.

That is a bad place to put a security property. A provider that returns the same key material for
every tenant — a misconfigured secret-store path, a cache keyed on the wrong thing, a stub left in
place — is a plausible bug, and an invisible one: everything still encrypts and decrypts correctly
within a tenant. The only symptom would be that two tenants holding the same document produce the
same fingerprint, which is precisely the cross-tenant confirmation a keyed fingerprint exists to
prevent. Mixing the tenant id into `info` makes isolation structural, matching what associated data
gives ciphertext, and it is applied to every purpose for consistency and defence in depth.

**Legacy reading cannot be written once, because there is no single legacy format.** The tempting
argument for it is "so an existing application can adopt the library without a data migration". The
problem is what a header-less value actually is: `iv || ciphertext || tag` and nothing else. It names
no key and no purpose label, so reading it requires the adopting application's *own* derivation
parameters — its labels, its key arrangement, its HKDF inputs — to be reachable through this
library's public API. "The legacy format" is therefore one format per adopter, and supporting it
means carrying configurable derivation forever so that each one can describe its own.

That is permanent public surface in exchange for a one-time, per-application problem that an offline
migration solves once and then never again. Refusing it avoids two kinds of complexity, permanently:

- **A version-sniffing heuristic**, and with it a genuine correctness trap. A header-less value
  begins with a random IV byte, so one in 256 of them starts with `0x01` and *structurally parses*
  as a v1 header. A reader accepting both formats cannot decide on the header alone; it has to
  attempt authenticated decryption and fall back on tag failure. That is a second code path, in the
  hot path of every read, forever, guarding against an ambiguity there is no need to have.
- **Configurable purpose labels.** Pre-existing rows were derived under whatever `info` value their
  application chose, so those values would have to stay settable through public API — and a settable
  purpose label is a settable key-use separation — the property `design.md` calls the cheapest
  correctness property in the whole design. Instead the
  labels are a fixed, documented enum: `tenantcrypt-field-v1`, `tenantcrypt-deterministic-v1` and
  `tenantcrypt-fingerprint-v1`.

The version byte still earns its place. Its purpose is *future* formats — an algorithm change, a
different AEAD — which is the argument for the header in the first place. A library whose first
release already reads a "legacy" format it never wrote is a different thing, and not the same
argument.

## Consequences

- A few bytes per value. Irrelevant.
- Key ids appear in stored data and are a public contract. `m1:t1` is the shape, and the naming
  scheme had to be settled before publication rather than after.
- The tenant id is part of the stored format in a second way: it is an input to the derivation, so
  **renaming a tenant makes its data unreadable and its fingerprints unmatchable.** Tenant ids must
  be stable identifiers — a UUID, not a slug or a domain name. Documented on `TenantId`.
- A stored value from any other system is rejected, not misread. Strictness is the feature.
- An application already holding header-less values adopts the library through a one-shot offline
  migration: read with its existing code, write with the library, writes stopped for the pass so no
  column ends up holding both formats. Documented as the adoption path rather than supported in
  code.
- Adding a further format later means a new version byte and a deliberate migration path — the
  thing the header exists to make possible.
