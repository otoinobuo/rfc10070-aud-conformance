# RFC 10070 — the rule under test, and the client-auth vs grant distinction

**Date:** 2026-11-09 · **Author:** Nobuo Otoi (ba-cybersecurity.com)
**Scope:** read-only static source reading of source-available OAuth AS/OP implementations. Nothing built, run, or sent; no issues/PRs opened.

## The RFC 10070 rule (2026-11; Updates RFC 7521/7522/7523/9126)

RFC 10070 tightens the `aud` requirement **for the client-authentication use of JWTs** — a client-assertion JWT presented with
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` (used by `private_key_jwt` and `client_secret_jwt`), and the same
JWTs at the PAR endpoint:

- Client authentication — **RFC 7523 §3 item 3 case B, as replaced by RFC 10070 §4**: the `aud` MUST be the AS's issuer identifier **as the sole
  audience value**; the AS MUST reject any JWT that does not contain its issuer identifier as its sole audience value; the **token endpoint URL MUST
  NOT be used** as an audience value.
- PAR — **RFC 9126 §2, as replaced by RFC 10070 §5**: the issuer identifier MUST be used as the sole value of the audience; reject otherwise.
- RFC 10070 does **not** explicitly forbid a single-element array; "sole audience value" is the operative phrase (a `[issuer]` that resolves to the
  issuer identifier is not what this note flags). What the implementations below accept is broader: the token-endpoint URL, and/or a multi-valued
  `aud` carrying additional endpoint URLs.
- There is **no backward-compatibility clause** letting an AS keep accepting the old values for client authentication.

Old behaviour now forbidden for client auth: old RFC 7523 §3 allowed the **token endpoint URL** as `aud`; old RFC 9126 §2 required the AS to accept
issuer id **OR** token endpoint URL **OR** PAR endpoint URL.

## The client-auth vs grant distinction (what scopes this review)

RFC 7523 is used two ways (§2.1 client authentication, §2.2 authorization grant). The RFC 10070 strict rule applies to the client-authentication use
only:

| Path | RFC 7523 §3 item 3 | `aud` rule under RFC 10070 | In scope? |
|---|---|---|---|
| **Client authentication** — the JWT authenticates the client (`private_key_jwt` / `client_secret_jwt`); also PAR (RFC 9126 §2 as replaced) | case B | STRICT: `aud` MUST be issuer-id, **sole value**; token-endpoint-URL MUST NOT be used | **Yes** |
| **Authorization grant** — JWT-bearer grant (`grant_type=…jwt-bearer`), the JWT IS the authorization | case A | LENIENT, essentially unchanged: `aud` MAY be issuer id **OR** token endpoint URL | **No — not flagged** |

Only the code path that validates the `aud` of a **client-assertion** JWT (and PAR) is in scope. The JWT-**bearer-grant** validator is out of scope
and is not reported as a divergence. In every implementation vetted I located the client-authentication `aud` validator specifically, not the grant
validator (grant validators: fosite `handler/rfc7523/handler.go`, Keycloak `JWTAuthorizationGrantType.java`, Authlib `jwt_bearer.py`;
node-oidc-provider and Spring have no JWT-bearer grant).

## Honest severity (conformance, not a vulnerability)

The underlying issue the rule fixes is a **previously disclosed, spec-level vulnerability**, not a per-implementation flaw. RFC 10070 §1 notes that a
client can authenticate an AS's issuer identifier but not its endpoints (RFC 8414); a malicious AS can therefore advertise a legitimate AS's
token-endpoint URL in its own metadata, and a client that reuses one key pair across ASes and sets `aud` to the endpoint URL hands the malicious AS a
client assertion it can replay to the legitimate one. This was disclosed across standards bodies (OpenID Foundation, 2025-01-24) and analyzed in
ePrint 2025/629; RFC 10070 is the fix.

A server accepting the token-endpoint URL as `aud` is a **necessary condition** for that attack, not the whole of it; the residual real-world risk is
governed by whether such key-reusing, endpoint-URL-audience clients exist against a given server. So each divergence found here is **Low — conformance /
robustness**, i.e. non-adoption of a published fix, not an authentication bypass in any one project. Any disclosure is framed as spec alignment, not a
CVE.
