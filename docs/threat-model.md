# Threat model

Read this before deciding whether the library fits. A library that claims more than it delivers is
worse than no library, and vague claims are how teams end up believing they have end-to-end
encryption when they do not.

## What this protects against

**Database-level compromise.** A stolen backup, a SQL-injection dump, a misconfigured replica,
direct access by someone with database credentials but not application secrets. No key material is
ever stored in the database, so ciphertext and fingerprints alone yield nothing.

**Single secret-store compromise.** Either key alone is useless. An attacker needs the deployment's
master key *and* the tenant's data key from the secret store.

**Cross-tenant leakage through derived keys.** Every tenant's derived key is distinct, so a
compromised tenant key exposes only that tenant. Fingerprints are tenant-scoped *by construction* —
the tenant id is mixed into the HKDF `info`, so identical content under two tenants cannot produce
the same fingerprint even if a key provider mistakenly hands both tenants the same key material.
Isolation is a property of the library, not a promise the provider has to keep.

**Ciphertext relocation across tenants, and header tampering.** The version, key id and tenant id
are authenticated as associated data, so a value moved from one tenant's row to another's fails to
decrypt rather than silently succeeding — even when both tenants resolve the same key id. Editing
the stored key id or version invalidates the tag. See ADR 0004.

**Key-use confusion.** Purpose labels through HKDF's `info` mean the fingerprint key and the
encryption key are cryptographically unrelated.

**Confirmation attacks on fingerprints.** Because fingerprints are keyed rather than bare digests,
someone holding a database dump cannot confirm that content they already possess is present.

## What this does not protect against

**A compromised application server.** This is not end-to-end encryption. The application decrypts
in process, so anyone with code execution, a heap dump, or the ability to call the application's own
code reads plaintext. If the threat model requires the operator not to see the data, this is the
wrong tool and no amount of key separation changes that.

**A compromised secret store, when the master key is reachable from the same place.** The two-key
model assumes the two live in genuinely different trust domains. Putting both in the same `.env` —
as the shipped reference key provider does, by construction — preserves only the
database-leak protection and nothing else. If you do that, say so out loud.

**Malicious insiders with application access**, for the same reason as the first item.

**Traffic analysis and metadata.** Row counts, timestamps, sizes, access patterns and foreign keys
are all in the clear, and often enough to infer what matters.

**Equality and frequency on any deterministic column.** This applies to both searchable
primitives — deterministic encryption and keyed fingerprints — and it is inherent, not a weakness of
the implementation: a value that can be compared can be counted. Anyone with the database sees which
rows share a value and how often each distinct value occurs, with no key at all. Over a
low-cardinality domain — a status, a country, a boolean, a tier — that frequency distribution usually
identifies the values outright. Use these only on high-cardinality values, and never as a way to make
a categorical column "encrypted".

**Recovery of a deterministically encrypted value by a key holder.** Unlike a fingerprint, which is
one-way, an AES-SIV value is recoverable. Anyone who can reach both keys can read the searchable
column, so it is not a safe place to put something you want irreversible. Use a fingerprint when the
index itself must not be reversible.

**Ordering, ranges and substring matching.** Not supported and not safe to approximate. Ciphertext
order is unrelated to plaintext order, and the schemes that do preserve order have a substantial
attack literature. Equality is the boundary.

**Similarity search over encrypted content.** Not provided, and not providable. A similarity vector
has to be derived from plaintext, so storing embeddings beside encrypted content leaks that plaintext
— published work on embedding inversion recovers substantial source text from embeddings alone. If
your application stores vectors for encrypted fields, those vectors are part of what you are
disclosing, and should be listed here for your deployment alongside everything else left in
plaintext.

**Relocating a ciphertext between columns of the same tenant.** The associated data binds the
version, the key id and the tenant id, so a value cannot be moved to another tenant or have its
header edited without failing to decrypt. It does **not** bind the column or the row, because a
stored value does not know where it is stored — and in the Spring module a JPA converter is handed
a value with no knowledge of the entity or column at all. So within one tenant, someone with write
access to the database can swap two values of the same kind between columns or rows and both will
still decrypt. If that matters, bind your own context: encrypt through the core API and include the
row identity in the plaintext you store.

**A mis-set ambient tenant context.** The optional Spring module resolves the tenant from a
thread-local, because a JPA converter cannot be passed one. If an application sets that context and
fails to clear it on a pooled thread, a later task on the same thread inherits it. Reads fail safe —
the tenant id is authenticated as associated data, so a wrong-tenant decrypt throws — but a
**write** under an inherited tenant encrypts one tenant's data under another's key, which is a
cross-tenant exposure that is silent at the time it happens. The library cannot detect this; it is a
property of how the context is populated. Use the module's `withTenant`, which restores the previous
value, rather than a bare `set`, and prefer the core API (explicit tenant parameter) on any stack
that hops threads.

**Derived key material in process memory.** Derived primitives are cached in a bounded LRU for as
long as the process lives, so a heap dump exposes derived keys for recently active tenants, not just
the value being decrypted at that instant. `clearCache()` drops them. This is a smaller version of
the first item on this list, not a separate protection.

**Data loss through key loss.** This is availability rather than confidentiality, and it is the
risk that runs in the other direction. Encrypted data is exactly as recoverable as the keys that
produced it: lose a tenant's data key and that tenant's rows are unrecoverable, and **lose the
master key and every tenant's rows are**, because one master key sits behind every derivation. Its
blast radius is the deployment, not a tenant. Retiring a master key version from the ring while rows
still reference it has the same effect, which is why retired versions stay readable until a rotation
pass has provably finished. Both keys need the backup and escrow discipline you would give the data
itself.

**Anything about what is left in plaintext.** Encrypting a column protects that column. Titles,
names, dates, amounts, search indexes and embeddings usually remain plaintext by necessity, and
they are frequently the sensitive part. The design's honesty depends on naming what is *not*
encrypted, per deployment.

## Assurance

None is claimed. No third-party cryptographic review, no audit, one author. Primitives come from
Tink rather than being hand-rolled, which reduces the surface where a subtle mistake can hide but
does not substitute for review. Anyone deploying this where a breach matters should have it
reviewed independently. See ADR 0005.
