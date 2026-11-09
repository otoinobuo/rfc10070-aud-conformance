# RFC 10070 client-authentication audience: a five-implementation conformance snapshot

A read-only source review of how five major open-source OAuth authorization-server
implementations validate the `aud` (audience) claim of a **client-authentication**
JWT, measured against the rule that [RFC 10070][rfc10070] (an IETF standard, 2026-11)
made MUST: the `aud` must be the server's **issuer identifier as the sole value**, and
the **token-endpoint URL must not be used**.

**Finding (default-branch HEAD, 2026-11-09): all five still accept the token-endpoint
URL** as the client-authentication `aud`; four of five also accept a multi-valued
`aud`. This is a **conformance snapshot, Low severity — not a vulnerability.** The rule
fixes a previously disclosed, specification-level weakness ([OpenID Foundation,
2025-01][oidf]; [ePrint 2025/629][eprint]); a server accepting the endpoint URL is only
one necessary condition for it, so this measures non-adoption of a published fix, not a
latent bug in any one project.

Nothing was built, run, or sent. No issues or PRs were opened.

## Matrix

| Server | Accepts as client-auth `aud` | Multi-valued `aud` | Conformant by config alone? | Class |
|---|---|---|---|---|
| ory/fosite (in Hydra) | configured token URL(s) only; issuer identifier **not** accepted | accepted | partial (no clean path) | divergent |
| node-oidc-provider | issuer / token / called-endpoint URL; issuer-only under FAPI 2.0 | accepted (no under FAPI 2.0) | yes (hook; strict under FAPI 2.0) | mixed |
| Keycloak | issuer / token / introspect / PAR / CIBA URLs | rejected by default | no (accept-set hardcoded) | mixed |
| Spring Authorization Server | issuer / token / introspect / revoke / PAR URLs | accepted | yes (`setJwtValidatorFactory`) | divergent |
| Authlib | developer-configured; sole-value not enforced | accepted | partial (needs `verify_claims` override) | divergent |

Only the **client-authentication** path (`private_key_jwt` / `client_secret_jwt`, and
PAR) is in scope. The **authorization-grant** path (JWT bearer, RFC 7523 §3 item 3
case A) stays lenient under RFC 10070 and is **not** flagged. Per-implementation
file:line evidence and pinned commit SHAs are in [`MATRIX.md`](MATRIX.md).

## The rule

- Client authentication — RFC 7523 §3 item 3 case B, as replaced by RFC 10070 §4:
  `aud` MUST be the issuer identifier as the sole value; MUST reject otherwise; the
  token-endpoint URL MUST NOT be used.
- PAR — RFC 9126 §2, as replaced by RFC 10070 §5: issuer identifier as the sole value.
- Authorization grant (out of scope) — RFC 7523 §3 item 3 case A: issuer identifier
  OR token-endpoint URL permitted.

The rule itself is not new: disclosed 2025-01, carried through
draft-ietf-oauth-rfc7523bis, FAPI 2.0, and OIDC Core errata before RFC 10070 finalized
it; adoption is phased (e.g. Keycloak 26.2 upgrade notes; Spring Security #18226).

## Files

- [`note.pdf`](note.pdf) — the two-page note (source: [`note.tex`](note.tex)).
- [`NOTE.md`](NOTE.md) — the note in Markdown.
- [`MATRIX.md`](MATRIX.md) — per-implementation deciding code, file:line, pinned SHAs.
- [`NOTES.md`](NOTES.md) — the RFC 10070 rule and the client-auth vs grant distinction.

## Method and honesty

For each project the client-authentication `aud` validator was located and its
accept-set read at a pinned commit, deliberately distinguished from the
authorization-grant validator. The multi-valued-`aud` behavior was confirmed in code.
The RFC 10070 rules, the disclosure history, and the pinned code were verified against
primary sources. Most of the review and drafting was performed with AI assistance; the
author re-opened each cited file:line at its pinned commit and confirmed the
classification before publishing.

## Cite

> Nobuo Otoi (ba-cybersecurity.com). RFC 10070 client-authentication audience rule: a
> five-implementation conformance snapshot. 2026.
> https://ba-cybersecurity.com/research/rfc10070-audience-conformance/

## License

Text and note: CC BY 4.0. — Nobuo Otoi (ba-cybersecurity.com), Tokyo, Japan.

[rfc10070]: https://www.rfc-editor.org/rfc/rfc10070
[oidf]: https://openid.net/
[eprint]: https://eprint.iacr.org/2025/629
