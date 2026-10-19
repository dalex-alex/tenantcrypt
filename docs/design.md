# Design

The two-key derivation, the two searchable primitives, and the stored formats.

## The two-key model

```
derived_key = HKDF-SHA256( ikm = server_master_key || tenant_data_key,
                           salt = none,
                           info = <purpose label> || "/" || tenant_id )
```

- **Server master key** — one per deployment, 32 bytes, from the environment or a secret store.
  Never in the database.
- **Tenant data key** — one per tenant, 32 bytes, from a secret store, typically created lazily on
  a tenant's first write. Supplying it is your `TenantKeyProvider` implementation's job.

Two properties follow, and they are worth stating separately because only the second one needs two
keys.

**No key material is ever in the database**, so a database leak — stolen backup, SQL-injection dump,
direct access — yields nothing. A single per-tenant key held in a secret store would give this too:
it is a property of where keys live, not of how many there are.

**Neither key alone decrypts anything**, so one compromised secret store is not sufficient. This is
what the second input actually buys, and it holds only if the two live in genuinely different trust
domains — with both in the same `.env`, as the shipped reference provider does by construction, only
the property above survives. Their exposure does differ in practice: tenant keys are numerous,
created lazily on first write, cached and passed through a provider interface, while the master key
is a single value read once at startup.

The master key has a second, operational job: it is half of every key id, so rotating it re-keys
every tenant at once, where per-tenant keys rotate one at a time. What it does *not* contribute is
tenant isolation — it is identical for every tenant, and separation comes from the per-tenant key
plus the tenant id in `info` (below).

Both claims are narrower than "encrypted", and the narrowness is the point; see
[`threat-model.md`](threat-model.md).

**Why per-tenant rather than per-user.** Colleagues, background jobs and inbound upload flows must
all read the same content. Per-user keys would make that impossible without key sharing, which is a
different and much larger design.

**Why the tenant id is in `info` as well.** It makes tenant isolation a property of this library
rather than of the key provider. A provider that mistakenly returns the same key material for two
tenants — a misconfigured secret-store path, a cache keyed on the wrong thing, a stub left in place
— still produces different derived keys per tenant. The consequence is that tenant ids are part of
the stored format: renaming a tenant makes its data unreadable, so they must be stable identifiers
(a UUID, not a slug). See ADR 0004.

## Key-use separation via the `info` label

Every derived key carries a purpose label through HKDF's `info` parameter, so a key derived for one
use is cryptographically unrelated to every other. The library defines three:

| Label | Used for |
|---|---|
| `tenantcrypt-field-v1` | randomised AES-256-GCM encryption |
| `tenantcrypt-deterministic-v1` | deterministic AES-SIV encryption |
| `tenantcrypt-fingerprint-v1` | keyed HMAC-SHA256 fingerprints |

Consequence: the fingerprint MAC key tells an attacker nothing about either encryption key, and
neither tells them anything about the other. This is the cheapest correctness property in the whole
design and the one most often skipped. The labels are a fixed enum rather than configuration,
because a settable purpose label is a settable key-use separation (ADR 0004).

## The stored formats

Both ciphers write a header naming the key that produced the value:

```
0x01  version[1] || key_id_len[1] || key_id[n] || iv[12] || ciphertext || tag[16]   randomised, AES-GCM
0x02  version[1] || key_id_len[1] || key_id[n] || siv_tag[16] || ciphertext         deterministic, AES-SIV
```

Strings are base64-wrapped; binary payloads are stored raw. Key ids are
`<masterKeyVersion>:<tenantKeyId>` — `m1:t1` is the shape — so either half of the derivation can
rotate independently. `version || key_id || tenant_id` is bound as AEAD associated data in both
formats, which makes the header tamper-evident and makes a ciphertext moved between tenants fail to
decrypt rather than silently succeed. Keyed fingerprints carry the same information as an `m1:t1:`
prefix (ADR 0009), so **every stored value names the key generation that produced it.**

That header is the reason rotation is possible at all. The layout application-level encryption
usually stores is whatever the AEAD emitted — `iv || ciphertext || tag`, with no key id, no version
and no algorithm identifier — and with no way to identify a value's key, changing a key orphans
every row written under the old one and no query finds them. Two bytes plus the key id up front;
unfixable afterwards. ADR 0004 records the decision and the format in full.

The library reads only the versions it defines. Anything else — including a header-less value
written by some other scheme — is rejected with `MalformedEnvelopeException` rather than guessed at.
ADR 0004 explains why there is no fallback reader.

## Rotation

The library ships primitives, not orchestration (ADR 0006): `keyIdOf` reports the generation a
stored value is on, `needsRotation` is the per-value predicate, and `rewrap` decrypts under the
named key and re-encrypts under the current one. Driving a pass over a table — batching,
checkpointing, resuming — is the caller's.

A pass has **three** obligations, not one:

1. re-wrap randomised ciphertext,
2. re-encrypt deterministic values,
3. **recompute fingerprints from plaintext.**

The third is the one an offline script is most likely to omit, because re-wrapping ciphertext looks
complete. A fingerprint's key is derived from both keys, so rotating either invalidates every stored
fingerprint; nothing is unrecoverable (the plaintext is still there) but every equality lookup
silently stops matching until the recompute runs. The generation prefix is what makes those rows
findable: `WHERE fp NOT LIKE '<current>:%'`.

## Searchable columns

AES-GCM is randomised: a fresh IV per call means the same plaintext produces different ciphertext
every time, so **ciphertext can never be compared for equality**. Any feature that needs "have I
seen this content before" — de-duplication, idempotency, join keys, uniqueness constraints — breaks
the moment the column is encrypted, and teams usually discover this after encrypting it.

There are two answers, and ADR 0009 records the rule for choosing between them.

### Deterministic encryption — the default

AES-SIV, as `TenantDeterministicCipher` under envelope version `0x02`. The same plaintext always
produces the same bytes for a tenant, so the column compares, joins and indexes normally — and the
value is recoverable, so one column is both the index and the data. It carries the versioned header
like any other ciphertext, and because the header is itself deterministic the value stays directly
comparable, which means stale rows are findable by key id after a rotation.

### Keyed fingerprints — the specialisation

A second, separately-derived key used for a keyed MAC over the content:

```
k_fp        = HKDF-SHA256( master || tenant_key, salt = none,
                           info = "tenantcrypt-fingerprint-v1" || "/" || tenant_id )
fingerprint = "<keyGeneration>:" || hex( HMAC-SHA256( k_fp, content ) )

  m1:t1:13623a4dada1d20f52b2888e78c5543e2a53c0fbce5982f934efc765ff2abd13
```

Deterministic, so it lives in a plaintext indexed column and compares and joins normally. Keyed, so
unlike a bare SHA-256 it does not let someone holding a database dump confirm that a document they
already possess is present. Tenant-scoped by construction, since the tenant id is part of the HKDF
`info`.

It keeps three advantages over deterministic encryption, and they are the reason it stays:

- **Fixed size**, so it indexes at any content size. AES-SIV output is plaintext length plus 16
  bytes, so a document-sized value cannot live in a btree index.
- **It can compare a normalised form** — lowercased, whitespace-collapsed, so a re-exported
  document still matches itself. A recoverable value would only recover the normalised text, which
  is useless as data.
- **It is irreversible even to a key holder.** HMAC is one-way; AES-SIV hands a key holder the
  plaintext.

### The cost both of them share

A value that can be compared can be counted. Anyone with the database sees which rows share a value
and how often each distinct value occurs, with no key at all. Over a low-cardinality domain — a
status, a country, a boolean — that frequency distribution usually identifies the values outright,
so neither primitive belongs there. Both suit high-cardinality values: an email address, an account
number, a document. Equality only — no ordering, no ranges, no `LIKE`, and no similarity search
(see the threat model, and ADR 0009 for why that boundary is a security one rather than a scope
one).

## Design notes

Questions a reader will raise, recorded so they are answered deliberately rather than discovered.

- **Concatenating the two keys as HKDF `ikm`, with no salt. Kept, and here is why.** HKDF-Extract
  with an absent salt is defined by RFC 5869 — it is treated as `HashLen` zero bytes — so the
  construction is not underspecified. The conventional alternative passes one key as `ikm` and the
  other as `salt`, and that convention exists because `salt` is designed to accept a *non-secret,
  possibly low-entropy* value. Here both inputs are full-entropy 32-byte secrets, so the asymmetry
  the convention is built around does not apply: Extract over the concatenation mixes both into the
  pseudorandom key exactly as intended, and `info` separates the key uses on top of that. Passing
  the master key as `salt` would be equally sound and no stronger. Kept as-is because changing it
  would mean maintaining two derivation paths forever for no security gain. This is recorded in
  `KeyDerivation`'s javadoc too, where a reader will actually meet the question.
- **Derivation does not run on every call.** Derived Tink primitives are cached in a bounded LRU
  keyed by `(tenant, key id, purpose)`, with an explicit `clearCache()`. Bounded because the
  natural cache key includes the tenant, and an unbounded map keyed by tenant is a memory leak in a
  system with many tenants. The cost is that a heap dump exposes derived keys for recently active
  tenants; the threat model says so.
- **Random 96-bit IVs are safe to roughly 2^32 messages per derived key.** Fine in practice, worth
  documenting as a limit, and another reason key versioning has to exist from day one.
- **The tenant is an explicit parameter in the core, and ambient only in the Spring module.** A JPA
  `AttributeConverter` receives a value and nothing else — no entity, no column, no tenant — so
  annotation-driven encryption is only possible with an ambient tenant. That thread-local therefore
  lives in `tenantcrypt-spring-boot-starter` and nowhere else, which keeps the core usable under any
  threading model. See ADR 0008, and the threat model on what a mis-set context costs.
