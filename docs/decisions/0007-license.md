# 0007 — Licence: Apache 2.0

- **Status:** Accepted
- **Date:** 2026-09-14 (accepted 2026-09-18)

## Decision

Apache License 2.0.

## Rationale

- **Explicit patent grant**, which MIT lacks. For cryptographic code this matters more than usual,
  and corporate users' legal review expects it.
- **Matches Tink** (ADR 0003), so no licence-compatibility question for the main dependency.
- Permissive, so the library can be read, vendored and adopted without a negotiation — which for a
  dependency this small is the difference between being used and being reimplemented.
- The `NOTICE` and explicit-contribution terms give attribution a defined place.

Copyleft was rejected: a library this small is most useful inside closed-source applications, and
a GPL would exclude exactly the deployments per-tenant encryption exists for.

## Contribution policy

Resolved on acceptance: **no CLA.** It is friction on a repo that carries no support obligation, and
Apache 2.0 section 5 already licenses inbound contributions under the same terms as the project, so
a CLA would add paperwork without adding rights this project needs.

`LICENSE` (the full Apache 2.0 text) and `NOTICE` are in the repository root.
