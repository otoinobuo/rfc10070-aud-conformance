# RFC 10070 client-assertion `aud` conformance matrix

**Date:** 2026-11-09 · **Author:** Nobuo Otoi (ba-cybersecurity.com) · read-only; nothing built, run, or sent.
**Rule under test:** see `NOTES.md`. In scope = the **client-authentication** (`private_key_jwt`/`client_secret_jwt`) and **PAR** `aud` validation
only; the JWT-bearer-**grant** path is excluded.
**Verdict key:** CONFORMANT = issuer-id as sole value, rejects the token-endpoint URL. DIVERGENT = still accepts the token-endpoint URL (and typically a
multi-valued `aud`) for client auth. MIXED = partially aligned (strict under a profile, or rejects multi-valued `aud` by default).

## Summary table (default-branch HEAD, 2026-11-09)

| # | Impl (lang) | Pinned SHA | Client-auth `aud` validator (file:line) | Accepts as `aud` | Multi-valued `aud` | Conformant by config alone? | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | **ory/fosite** (Go; in Hydra) | fosite `a5f0b09`; Hydra `4174065` | `client_authentication.go` check+match; set `fositex/config.go:230-236` | configured token URL(s) only; issuer id **not** accepted | accepted | partial (no clean path) | DIVERGENT |
| 2 | **node-oidc-provider** (JS) | `3ed87be` | `jwt_client_auth.js:48-58`; set `oidc_context.js:133-135`; FAPI check `defaults.js:632-638` | issuer / token / called-endpoint URL (default); **issuer-only under FAPI 2.0** | accepted (default); rejected under FAPI 2.0 | yes (hook; strict under FAPI 2.0) | MIXED |
| 3 | **Keycloak** (Java) | `d4d5554` | `AbstractBaseJWTValidator.java:126-137`; set `JWTClientValidator.java:29-39` | issuer / token / introspect / PAR / CIBA URLs | **rejected by default** (`OIDCProviderConfig.java:110`) | no (accept-set hardcoded) | MIXED |
| 4 | **Spring Authorization Server** (Java) | `4283973` | `JwtClientAssertionDecoderFactory.java:174,194-212` | issuer / token / introspect / revoke / PAR URLs | accepted | yes (`setJwtValidatorFactory`) | DIVERGENT |
| 5 | **Authlib** (Python) | `0f9826c` | `rfc7523/client.py:64-94` (`verify_claims`), `get_audiences` | developer-configured; sole-value not enforced | accepted | partial (needs `verify_claims` override) | DIVERGENT |

**All five still accept the token-endpoint URL** as the client-authentication `aud` (the value RFC 10070 now forbids). Four of five also accept a
multi-valued `aud`; Keycloak rejects it by default. Two are MIXED (node-oidc-provider strict under FAPI 2.0; Keycloak default-rejects multi-valued
`aud`). None enforces issuer-id-as-sole-value on the default client-authentication path. Of the four that implement PAR (fosite/Hydra,
node-oidc-provider, Keycloak, Spring), PAR routes through the same client-auth validator and diverges the same way; **Authlib does not implement PAR**.

---

## Per-impl deciding code and detail

### 1. ory/fosite — fosite `a5f0b09`, in-tree in Hydra `4174065`
The standalone `ory/fosite` repo's last commit is 2025-07-03 (`a5f0b09` = HEAD); Hydra carries fosite in-tree and the logic is identical there. The
accept-set is whatever `Config.GetTokenURLs()` returns; the library default (`config_default.go`) is `[]string{c.TokenURL}`, and Hydra's wiring
(`fositex/config.go:230-236`) returns token-URL variants only.
```go
if !audienceMatchesTokenURLs(claims, f.Config.GetTokenURLs(ctx)) { return nil, ...token-endpoint error... }
func audienceMatchesTokenURL(claims, tokenURL) bool {
    if audiences, ok := claims["aud"].([]interface{}); ok { for _, a := range audiences { if a == tokenURL { return true } }; return false } // array aud
    return claims.VerifyAudience(tokenURL, true)  // single aud == token URL
}
```
Strongest divergence of the set: it **only** matches the token endpoint URL(s) and **never** accepts the issuer identifier — the inversion of the new
MUST. Accepts a multi-valued `aud` (any element equal to a token URL). PAR uses the same `AuthenticateClient`, so it diverges identically. Config path:
a token-URL string is configurable, but a multi-valued `aud` still passes, so there is no clean config-only route to sole-value conformance.

### 2. node-oidc-provider — `3ed87be`
```js
// jwt_client_auth.js:48-58
if (Array.isArray(payload.aud)) { if (!payload.aud.some((aud) => acceptedAud.has(aud))) throw ...; }
else if (!acceptedAud.has(payload.aud)) throw ...;
// oidc_context.js:133-135
clientJwtAuthExpectedAudience() { return new Set([this.issuer, this.urlFor('token'), this.urlFor(this.route)]); }
```
Default accepts issuer id, token endpoint URL, and the called endpoint URL, and accepts arrays. **Under the FAPI 2.0 profile**
(`defaults.js:632-638`) the default assertion check rejects `aud !== issuer` (strict exact match, so arrays are rejected too) — so it is already
conformant under FAPI 2.0 and lenient otherwise = **MIXED**. The accepted set is also replaceable via `clientJwtAuthExpectedAudience`, so config-only
conformance is available.

### 3. Keycloak — `d4d5554`
```java
// AbstractBaseJWTValidator.java:126-137
if (!token.hasAnyAudience(expectedAudiences)) return failure("Invalid token audience");
if (!multipleAudienceAllowed && token.getAudience().length > 1) return failure("Multiple audiences not allowed");
// JWTClientValidator.java:29-39 expected set:
{ issuerUrl, tokenUrl, tokenIntrospectUrl, parEndpointUrl, backchannelAuthenticationUrl }
```
Accepts the token endpoint URL (and three other endpoint URLs). Partial hardening: a multi-valued `aud` is **rejected by default**
(`OIDCProviderConfig.java:110`, `isAllowMultipleAudiencesForJwtClientAuthentication` off unless configured). Keycloak's 26.2 upgrade notes already
recommend the issuer identifier as `aud`, so the remaining gap is a documented phased design, not oversight = **MIXED**. The accept-set itself is
hardcoded, so config alone does not reach sole-value conformance. `client_secret_jwt` uses the same set (`JWTClientSecretValidator extends
JWTClientValidator`). PAR shares the expected set.

### 4. Spring Authorization Server — `4283973`
```java
// :194-212  audienceList = issuer, asUrl(issuer, tokenEndpoint), asUrl(issuer, introspectionEndpoint),
//                          asUrl(issuer, revocationEndpoint), asUrl(issuer, pushedAuthorizationRequestEndpoint)
// :174,179-192  containsAudience(): true if ANY element of a multi-valued aud is in audienceList
```
Accepts issuer, token URL, introspection URL, revocation URL, PAR URL; a multi-valued `aud` passes if any element is in the set. DIVERGENT on both
counts. PAR URL is in the same set and uses the same decoder factory (`OAuth2ClientAuthenticationConfigurer.java:199-209`). Config path: the validator
factory is replaceable via `setJwtValidatorFactory` (public). Spring Security #18226 (2025) records the maintainer deferring the change until the draft
was approved.

### 5. Authlib — `0f9826c`
```python
# rfc7523/client.py:64-94  JWTBearerClientAssertion.verify_claims
audiences = self.get_audiences()
options = { ..., "aud": {"essential": True, "values": audiences}, ... }   # membership match
jwt.JWTClaimsRegistry(leeway=self.leeway, **options).validate(claims)
```
`get_audiences()` is abstract, but its docstring instructs implementers to return `["https://example.com/oauth/token", "https://example.com"]` —
token endpoint URL plus issuer. joserfc's `values` option is a membership test (a list `aud` matches if any element is in the set), so a multi-valued
`aud` passes and `[issuer]` also passes, but **sole-value is not enforced** — reaching sole-value requires a `verify_claims` override. By its shipped
guidance this is DIVERGENT. Authlib has no PAR (RFC 9126) implementation.

---

## Severity (conformance, not a vulnerability)

None is an authentication bypass; each divergence is **Low — conformance/robustness**. The reasoning is in `NOTES.md`: the audience restriction fixes a
previously disclosed, spec-level vulnerability (OIDF 2025-01; ePrint 2025/629) in which a malicious AS advertises a legitimate AS's token-endpoint URL;
a server accepting the token-endpoint URL as `aud` is a **necessary condition** for that attack, and the residual real-world risk depends on whether
key-reusing, endpoint-URL-audience clients exist. This matrix therefore measures non-adoption of a published fix, not a latent bug in any single
project. The multi-valued-`aud` acceptance is the aspect closest to a replay primitive, and it still requires a client to mint a multi-audience
assertion; Keycloak rejects it by default.
