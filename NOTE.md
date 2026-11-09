# RFC 10070 client-authentication audience rule: a five-implementation conformance snapshot

**Nobuo Otoi** (ba-cybersecurity.com) — independent cybersecurity researcher, Tokyo, Japan
**Draft note, 2026-11-09.** A point-in-time measurement against each project's default-branch HEAD as of 2026-11-09; implementations and the pinned commits move.

## Summary

RFC 10070, an IETF standard published 2026-11 ("Updates to OAuth 2.0 JWT Client Authentication and Assertion-Based Authorization Grants"; updates RFC 7521/7522/7523/9126), tightened the audience (`aud`) rule for the JWT used in **client authentication** (`private_key_jwt` / `client_secret_jwt`, and the PAR endpoint): the `aud` MUST be the authorization server's **issuer identifier as the sole value**, and the token-endpoint URL **MUST NOT** be used. The **authorization-grant** path (JWT bearer, RFC 7523 §3 item 3 case A) stays lenient and is out of scope here.

A read-only source review of five major, source-available OAuth authorization-server implementations finds that, against their default-branch HEADs, **all five still accept the token-endpoint URL as the client-authentication `aud`** — the value RFC 10070 now forbids. Four of the five also accept a multi-valued `aud`. Two are partially aligned (Keycloak rejects multi-valued `aud` by default; node-oidc-provider is strict under its FAPI 2.0 profile).

| Implementation | Pinned commit | Deciding code | Accepted `aud` (client auth) | Multi-valued `aud` | Conformant by config alone? |
|---|---|---|---|---|---|
| ory/fosite (in-tree in Hydra) | fosite `a5f0b09`; Hydra `4174065` | `client_authentication.go` match; `fositex/config.go:230-236` (`GetTokenURLs`) | the configured token URL(s) only — library default `[]string{TokenURL}`; **issuer identifier not accepted** | accepted | partial (no clean path: a token-URL string can be set, but multi-aud still passes) |
| node-oidc-provider | `3ed87be` | `jwt_client_auth.js:48-58`, `oidc_context.js:133-135`; FAPI check `defaults.js:632-638` | issuer id / token URL / the called endpoint URL (default); **under FAPI 2.0: issuer id only** | accepted (default); rejected under FAPI 2.0 | yes (`clientJwtAuthExpectedAudience` hook; already strict under FAPI 2.0) — **MIXED** |
| Keycloak | `d4d5554` | `AbstractBaseJWTValidator.java:126-137`, `JWTClientValidator.java:29-39` | issuer / token / introspect / PAR / CIBA URLs | **rejected by default** (`OIDCProviderConfig.java:110` default false) | no (accept-set hardcoded; only the multi-aud flag is configurable) — **MIXED** |
| Spring Authorization Server | `4283973` | `JwtClientAssertionDecoderFactory.java:174,194-212` | issuer / token / introspect / revoke / PAR URLs | accepted | yes (`setJwtValidatorFactory`, public) |
| Authlib | `0f9826c` | `rfc7523/client.py:64-94` | developer-configured (`get_audiences`); joserfc does a containment check, so `[issuer]` passes but sole-value is not enforced | accepted | partial (needs a `verify_claims` override for sole-value) |

Of the four projects that implement PAR (fosite/Hydra, node-oidc-provider, Keycloak, Spring), each routes PAR through the same client-authentication validator and diverges the same way; Authlib does not implement PAR.

## Why this is Low and conformance-framed — not a new vulnerability

The per-implementation severity is **Low**, and this is **not** a report of a novel flaw in any one project. But it is worth being precise about what the underlying issue is, because it is a real one.

The audience restriction fixes a **previously disclosed, spec-level vulnerability**. A malicious authorization server can advertise a legitimate AS's token-endpoint URL in its own metadata — a client can authenticate an AS's *issuer* identifier but not its endpoints (RFC 8414), which RFC 10070 §1 notes directly. A client that reuses one key pair across authorization servers and sets `aud` to the endpoint URL will therefore hand the malicious AS a client assertion it can replay to the legitimate AS. This was disclosed across standards bodies (OpenID Foundation, 2025-01-24) and analyzed in the literature (ePrint 2025/629); RFC 10070 §1 calls it a "security vulnerability," and RFC 10070 is the fix.

A server accepting the token-endpoint URL as `aud` is a **necessary condition** for that attack; the residual real-world risk is governed by whether such key-reusing, endpoint-URL-audience clients exist against a given server. So this note measures **non-adoption of a published fix across the server ecosystem**, not a latent bug in any single project — hence Low, conformance-framed, and suitable (if raised at all) as a conformance heads-up rather than a vulnerability report.

## The rule is not new, and adoption is deliberately phased

The restriction has been public for roughly two years: disclosed 2025-01 (OIDF), analyzed in 2025 (ePrint 2025/629), and carried through draft-ietf-oauth-rfc7523bis, FAPI 2.0, and OIDC Core errata before RFC 10070 finalized it in 2026-11. Implementers have had notice and are moving on their own schedules: Keycloak's 26.2 upgrade notes already recommend the issuer identifier as `aud`, and Spring Security #18226 records the maintainer deferring the change until the draft was approved. RFC 10070 itself advises phased adoption — §6 recommends updating clients before or alongside server enforcement, and §4 cautions that rejecting JWTs without an explicit `typ` is NOT RECOMMENDED. A server still accepting the old `aud` may therefore be mid-transition by design, not negligent. The value of this snapshot is as a timed measurement of that transition across the ecosystem, not as a scorecard.

## The rule (RFC 10070, verified against the primary text)

- Client authentication — RFC 7523 §3 item 3 case B, as replaced by RFC 10070 §4: the `aud` "MUST indicate only the issuer identifier of the intended authorization server"; the server "MUST reject any JWT that does not contain its issuer identifier as its sole audience value"; the token-endpoint URL "MUST NOT be used as an audience value."
- PAR — RFC 9126 §2, as replaced by RFC 10070 §5: the issuer identifier "MUST be used as the sole value of the audience"; reject otherwise.
- Authorization grant (out of scope) — RFC 7523 §3 item 3 case A: "An authorization server MAY be identified by either its issuer identifier or its token endpoint URL."
- RFC 10070 does not forbid a single-element array; "sole audience value" is the operative phrase. No backward-compatibility text permits servers to keep accepting the old values.

## Method (reproducible)

Read-only source review; no build, no network, nothing sent. For each project the **client-authentication** `aud` validator was located and its accept-set read at the pinned commit — deliberately distinguished from the authorization-grant validator (fosite `handler/rfc7523/handler.go`, Keycloak `JWTAuthorizationGrantType.java`, Authlib `jwt_bearer.py`; node-oidc-provider and Spring have no JWT-bearer grant). The multi-valued-`aud` behavior was confirmed in code for each (including joserfc's containment check and Keycloak's default-false flag). The RFC 10070 normative text, the OIDF disclosure, and the ePrint abstract were read against primary sources. Per-implementation line-level detail: `MATRIX.md`.

## AI-assistance disclosure

Most of the source review and drafting was performed with AI assistance. Before finalizing, the author re-opened each cited file:line at its pinned commit and confirmed the classification, and verified the RFC 10070 rules, the client-auth-vs-grant split, and the disclosure history against the primary documents.

*— Nobuo Otoi (ba-cybersecurity.com)*
