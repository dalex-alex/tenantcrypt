# 0005 — No security assurance claims

- **Status:** Accepted
- **Date:** 2026-09-14

## Decision

Every user-facing surface — README, package docs, threat model — states plainly that there has been
no third-party cryptographic review and no audit, and that the library has a single author. Never
soften it. Never add a security claim the threat model does not support.

## Rationale

Three reasons, in order of weight.

**It is the honest thing to do.** Someone could deploy this over real user data, and the decision
to do that should be made with the actual facts. A permissive licence and a free download do not
make the assurance gap smaller; they only make it easier to overlook.

**A stated limit is more useful than an unqualified claim.** "Encrypted at rest" tells a reader
nothing they can act on. A threat model that names what is *not* protected — plaintext columns,
frequency leakage on deterministic values, a compromised application process — lets them decide
whether this library fits, which an unqualified claim actively prevents.

**It removes the pressure to over-claim later.** Written down as a decision, it is not renegotiated
in a weak moment while writing marketing copy.

## Consequences

- Some potential users will decline on these grounds. Correct outcome.
- Any future third-party review supersedes this ADR explicitly rather than quietly.
- The threat model's "what this does not protect against" section is a first-class part of the
  documentation and is never trimmed for brevity.
