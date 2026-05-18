# Bearer Token (M2M) Authentication

Opt-in path that lets API clients present `Authorization: Bearer <jwt>` to
authenticate without going through the cookie-based OIDC redirect flow.
Designed for machine-to-machine (M2M) traffic — services calling other
services with tokens minted by your OIDC provider.

The bearer path lives next to the cookie path: both go through the same
post-auth pipeline (`forwardAuthorized`) that injects identity headers,
checks `allowedRolesAndGroups`, applies security headers, and forwards to
the backend. The only thing that differs is how the principal is established
for that single request.

## Quick start

```yaml
enableBearerAuth: true
audience: https://api.example.com  # REQUIRED when bearer is enabled
clientID: my-api-client-id
providerURL: https://issuer.example.com
sessionEncryptionKey: <32+-byte secret>
callbackURL: /oauth2/callback
```

That is the minimum. Everything else has a secure default.

## Obtaining bearer tokens from your OIDC provider

The middleware only **validates** bearer tokens — minting them is the IdP's job. For M2M traffic the canonical mint flow is OAuth 2.0 **`client_credentials`** (RFC 6749 §4.4); some providers require **JWT bearer assertion** (RFC 7523) instead.

```
┌────────────┐  POST /token                    ┌──────────┐
│  client    │ ───────────────────────────────►│  IdP     │
│  (service) │   grant_type=client_credentials │ /token   │
│            │   client_id=…                   │          │
│            │   client_secret=…  (or JWT)     │          │
│            │   audience=https://api.…   ←── critical    │
│            │   scope=api:read …                         │
│            │ ◄───────────────────────────────│          │
│            │     access_token (JWT)          │          │
└────────────┘                                 └──────────┘
         │
         │  GET /protected
         │  Authorization: Bearer <access_token>
         ▼
   Your service (behind Traefik + this plugin)
```

The IdP returns a JWT signed by the same JWKs the middleware already trusts (it discovers them from `providerURL`/.well-known). On the first protected request, the middleware verifies signature + issuer + **audience** + `exp` + identifier claim, then forwards downstream with `X-Forwarded-User` set.

### Minimal worked example (Auth0-shape)

```bash
# 1. Mint a token
curl -s -X POST https://issuer.example.com/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":    "client_credentials",
    "client_id":     "your-m2m-client-id",
    "client_secret": "your-m2m-client-secret",
    "audience":      "https://api.example.com",
    "scope":         "api:read api:write"
  }'
# → {"access_token":"eyJhbGciOiJSUzI1NiIs…","token_type":"Bearer","expires_in":86400,…}

# 2. Use it
curl -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs…' https://api.example.com/protected
```

The `audience` field in the token request **must match** the `audience` you configured on the middleware. Mismatch → 401 with `Bearer error="invalid_token"`.

### Per-provider quick reference

| Provider | Grant | Token endpoint | Audience parameter | Notes |
|---|---|---|---|---|
| **Auth0** | `client_credentials` | `https://TENANT.auth0.com/oauth/token` | `audience=<your API identifier>` | Register an "API" + "Machine to Machine Application" authorised against that API. Without `audience` you get an opaque /userinfo token, which the bearer path rejects. See `docs/AUTH0_AUDIENCE_GUIDE.md`. |
| **Okta** | `client_credentials` | `https://TENANT.okta.com/oauth2/default/v1/token` | Configured in the authorization server; default `aud` is the auth-server URL | Service app must enable the `client_credentials` flow and be granted the requested scopes. |
| **Keycloak** | `client_credentials` | `https://kc/realms/REALM/protocol/openid-connect/token` | Configure an "Audience" mapper on a client scope, or use `client_id` as the audience | Client must have `serviceAccountsEnabled: true` plus role mappings. |
| **Entra ID / Azure AD** | `client_credentials` (v2.0 endpoint) | `https://login.microsoftonline.com/TENANT/oauth2/v2.0/token` | Pass `scope=<App ID URI>/.default`; `aud` ends up being the API's App ID URI | Requires an App Registration + API permissions + admin consent. **Use the v2.0 endpoint** — v1 issues Microsoft-proprietary access tokens that are opaque to non-Microsoft clients. |
| **AWS Cognito** | `client_credentials` | `https://YOUR_DOMAIN.auth.REGION.amazoncognito.com/oauth2/token` | Scopes from a "Resource Server" attached to your User Pool | App client must have `client_credentials` flow enabled. Use HTTP **Basic** auth header for `client_id:client_secret`. |
| **GitLab** | `client_credentials` | `https://gitlab.com/oauth/token` | Audience matches the GitLab issuer | Rarely used for protecting external APIs; better suited for GitLab's own resources. |
| **Google** | **JWT bearer (RFC 7523)** — *not* `client_credentials` | `https://oauth2.googleapis.com/token` | Signed assertion JWT carries `aud=https://oauth2.googleapis.com/token`; resulting access token is **opaque** unless you specifically request a Google-issued JWT for your API | Google service-account flow is not the best fit for this middleware (opaque tokens are rejected on the bearer path). Run Auth0 / Okta / Keycloak in front, or use ID-token-based flows on the cookie path. |

### RFC 7523 (JWT bearer assertion) — secretless alternative

When shared secrets are forbidden (FAPI, internal compliance), swap `client_secret` for a signed JWT assertion:

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<JWT signed by the client's private key>
```

The assertion JWT carries `iss=<client_id>`, `sub=<client_id>`, `aud=<token endpoint>`, `exp`. The IdP verifies the signature against a public key you've pre-registered and returns an access token.

This middleware already supports JWT assertions on the *middleware → IdP* hop via `clientAuthMethod: private_key_jwt` (see `docs/CONFIGURATION.md`). For the *client → IdP* hop, the same pattern applies — the client signs its own assertion.

### Operational notes

- **Token TTL is typically 1–24 hours.** Clients should refresh on `401`, not on a polling timer — saves the IdP.
- **Cache and reuse tokens.** The middleware caches verified tokens too, so repeated presentations are cheap. Clients SHOULD reuse a token until ~80 % of `expires_in`.
- **JWKS rotation is transparent.** The middleware auto-refreshes its JWKS cache when the IdP rotates keys. Clients don't need to do anything.
- **Revocation is generally not per-token** with `client_credentials`. If you need real-time revocation, set `requireTokenIntrospection: true` on the middleware and the IdP is consulted on every cache miss.
- **`scope` vs `audience`.** Scope says *what the client may do*; audience says *which service the token is for*. The middleware enforces audience; the backend service should enforce scope.
- **Secret hygiene.** Store `client_secret` in a secrets manager (Vault, AWS Secrets Manager, Kubernetes `Secret`). For higher assurance, switch the client to `private_key_jwt` (no shared secret at all).

### Quickest validation loop

```bash
# 1. Mint
TOKEN=$(curl -s -X POST https://issuer.example.com/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"…","client_secret":"…","audience":"https://api.example.com"}' \
  | jq -r .access_token)

# 2. Inspect claims to confirm aud/iss/exp match the middleware config
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# 3. Hit the protected route
curl -i -H "Authorization: Bearer $TOKEN" https://api.example.com/protected
```

`HTTP/1.1 200` with `X-Forwarded-User` on the backend confirms the loop works end-to-end. `401` with `WWW-Authenticate: Bearer error="invalid_token"` plus a middleware debug log explaining the rejection (audience mismatch, ID token presented, `iat` outside the 24h window, etc.) confirms the hardening is firing as designed.

## Threat model and design rules

Bearer authentication has materially different security properties from
cookie sessions: no `HttpOnly`/`Secure`/`SameSite` shielding, the token is
visible in headers and logs, and it's easier to exfiltrate. The bearer path
treats every one of these as a first-class concern.

| Property | Behaviour | Why |
|---|---|---|
| Default state | `enableBearerAuth=false` | Bearer is opt-in; existing deployments observe no change. |
| Audience | **Mandatory.** Startup fails if `audience` is empty when bearer is enabled. | Eliminates the "token issued for service B accepted by service A" confusion attack. |
| Token format | JWT only (3 segments, JOSE-encoded). Opaque tokens are not accepted on the bearer path. | Matches the validation pipeline; opaque tokens require introspection only and bypass JWT-specific defences. |
| `alg` allowlist | Hard-pinned asymmetric: `RS256/384/512`, `PS256/384/512`, `ES256/384/512`. Checked **before** any JWKS fetch. | Denies `alg=none` and `alg=HS*` probes; prevents attacker noise from amplifying into JWKS round-trips. |
| `kid` hardening | Max 256 bytes; charset `[A-Za-z0-9._\-=]`. Checked **before** JWKS fetch. | Prevents cache-key explosion / pathological-`kid` JWKS amplification. |
| Token type | ID tokens are explicitly rejected (`nonce` claim, `typ: at+jwt`, `token_use=id`, scope/aud heuristics — reuses the existing `detectTokenType` helper). | ID tokens are not API credentials; treating them as such is classic token confusion. |
| Multi-audience | When `aud` is an array of length > 1, the token must carry `azp == clientID`. | OIDC §2 hardening against tokens minted for one client being replayed by another. |
| `iat` upper-age | Rejects tokens older than `maxTokenAgeSeconds` (default 24h). | Bounds clock-manipulation / forever-token abuse, even if `exp` is far in the future. |
| Identifier claim | `bearerIdentifierClaim` (default `"sub"`). Resolved value drives `X-Forwarded-User`. | Decoupled from the cookie path's `UserIdentifierClaim` (default `email`) so the M2M flow can never accidentally trust an unverified email. |
| Identifier sanitisation | Length cap (`maxIdentifierLength`, default 256). Rejects control chars, Unicode bidi-overrides (U+202A–U+202E, U+2066–U+2069), and the delimiters `, ; =`. | Defence in depth against downstream header injection / log injection / admin-UI spoofing. |
| JTI replay marking | Bearer path skips the JTI **Set** (so the same token can be reused until `exp`) but the **Get** stays active. | Allows legitimate bearer reuse without false-positive replay detection; revoked tokens (added to the blacklist by `RevokeToken`) still fail immediately. |
| Mixed bearer + cookie | **Cookie wins by default.** Flip to bearer-wins with `bearerOverridesCookie=true`. | Safer against browser/extension/proxy bearer injection scenarios. The cookie is the authoritative authenticator when present. |
| `Authorization` strip | `stripAuthorizationHeader=true` by default. | Keeps the raw token out of downstream services and their logs. |
| Excluded URLs | `Authorization` is stripped on excluded paths when `enableBearerAuth=true`. | Prevents bearer leakage into public health/metrics endpoint logs and prevents recon via excluded paths. |
| Per-IP throttle | After `bearerFailureThreshold` consecutive 401s from one source IP within `bearerFailureWindowSeconds`, further bearer requests from that IP return `429 Too Many Requests` + `Retry-After` for `bearerFailurePenaltySeconds`. | Limits offline-guessing-style attacks and protects the shared rate-limiter / JWKS endpoint. |
| Optional introspection | `requireTokenIntrospection=true` calls RFC 7662 introspection on every cache miss. Introspection result is cached briefly. Endpoint failure returns `503` (distinguishes infra outage from credential rejection). | Real-time revocation for high-assurance environments. Adds per-request IdP latency. |
| Response shape | `401 Unauthorized` with generic body. `WWW-Authenticate: Bearer error="invalid_token"` per RFC 6750 §3 (toggleable via `bearerEmitWWWAuthenticate`). `403` for roles/groups denial. `429` for throttle. `503` for introspection-endpoint outage. | Auditable from spec to code; reason categories never leak into the response body. |
| Logging | Failure reason + identifier hash (SHA-256 truncated to 8 hex chars) logged at debug. Raw tokens are never logged. | Audit trail without secrets-in-logs. |

## Configuration reference

| Field | Default | Description |
|---|---|---|
| `enableBearerAuth` | `false` | Master switch for the bearer path. |
| `audience` | (unset) | **Required** when `enableBearerAuth=true`. Reuses the existing global `audience` field. |
| `bearerIdentifierClaim` | `"sub"` | JWT claim used as the principal identifier. `"email"` is rejected at startup. |
| `stripAuthorizationHeader` | `true` | Remove the `Authorization` header before forwarding to the backend. Disable only when a downstream needs to re-verify the bearer. |
| `bearerEmitWWWAuthenticate` | `true` | Include `WWW-Authenticate: Bearer error="..."` on 401 responses (RFC 6750 §3). Disable to reduce recon signal. |
| `bearerOverridesCookie` | `false` | Cookie wins when both are present (default). Set `true` for the AWS/GCP/Kubernetes bearer-wins convention. |
| `maxTokenAgeSeconds` | `86400` | Upper bound on `iat` claim age (24h). Set `0` to disable the check (not recommended). |
| `maxIdentifierLength` | `256` | Length cap for the post-sanitisation identifier. |
| `bearerFailureThreshold` | `20` | Consecutive 401s from one IP that trip the throttle. |
| `bearerFailureWindowSeconds` | `60` | Rolling window over which 401s are counted. |
| `bearerFailurePenaltySeconds` | `60` | Duration of the 429 penalty box after the threshold trips. |
| `requireTokenIntrospection` | `false` | Call RFC 7662 introspection on every cache miss. Adds per-request IdP latency. |

## What the bearer path does NOT do

- **Human-user / browser flows.** The bearer path is M2M-only in this
  iteration. Browser SPAs that want to attach a bearer to fetch calls work
  if your backend treats them as machine clients, but the spec defaults are
  tuned for service-to-service traffic.
- **Opaque access tokens.** Tokens must be JWTs. Introspection is a
  revocation overlay on top of JWT verification, not a substitute for it.
- **`email_verified` enforcement.** The bearer path rejects `email` as the
  identifier claim at startup precisely because `email_verified` is not
  enforced in this iteration. Adding human-user bearer support is a
  follow-up that must include this check.
- **mTLS / API keys.** Out of scope. The `principal` abstraction enables
  adding these later as additional auth methods that produce a principal
  for the shared `forwardAuthorized` pipeline.
- **SSE / WebSocket bypass with bearer.** Bypass paths keep their existing
  cookie-only behaviour; bearer headers are ignored on those endpoints.
  Documented limitation; widen by removing the bypass if you need bearer on
  streaming endpoints.

## Operational guidance

- **Always set `strictAudienceValidation: true` when bearer is enabled.**
  Startup logs a recommendation if you don't.
- **Set a tight `maxTokenAgeSeconds`** for environments where tokens are
  expected to be minted frequently — the default 24h is conservative.
- **Enable `requireTokenIntrospection`** if your IdP supports it and
  revocation latency matters. Bearer-path introspection caches results for
  a short window per token.
- **Monitor 429s.** Sustained 429 traffic indicates either a buggy client
  loop or an active credential-stuffing attempt. The throttle is your
  primary signal for both.
- **`stripAuthorizationHeader=false` extends the token's blast radius** to
  every downstream service that sees the request. Treat those services'
  logs as token stores.
- **Bearer reuse is normal.** Don't enable per-token rate limiting; that's
  what `bearerFailureThreshold` is for (per-IP, not per-token).
- **Cookie-wins is the safer default.** Only flip `bearerOverridesCookie`
  if you control all clients and have audited that none of them present a
  cookie alongside a bearer they don't intend to authenticate with.

## Failure response matrix

| Trigger | Status | Body | `WWW-Authenticate` |
|---|---|---|---|
| Empty bearer after prefix | 401 | `Unauthorized` | `Bearer error="invalid_request"` |
| Token over `MaxLength` | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Not a 3-segment JWT | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Disallowed `alg` (e.g. none, HS*) | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Missing / oversized / bad-charset `kid` | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Signature / issuer / audience / `exp` failure | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| `iat` older than `maxTokenAgeSeconds` | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Multi-audience token without matching `azp` | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Detected as ID token | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| JTI blacklisted (revoked) | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Introspection reports `active=false` | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Introspection endpoint failure | 503 | `Service Unavailable` | (none) |
| Identifier claim missing / empty | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Identifier fails sanitisation | 401 | `Unauthorized` | `Bearer error="invalid_token"` |
| Per-IP failure threshold tripped | 429 | `Too Many Requests` | (none); `Retry-After: <bearerFailurePenaltySeconds>` |
| Roles / groups not allowed | 403 | `Access denied` | (none) |

## Known follow-ups (deferred)

These are documented as future work, not blockers:

- **Human-user bearer with `email_verified` enforcement.** Requires
  decoupling the email-claim guard from the startup rejection and adding a
  per-request `email_verified=true` check.
- **Introspection respects `client_assertion`.** The existing introspection
  helper uses `client_secret_basic` only; operators on `private_key_jwt`
  will see introspection silently use basic auth.
- **Per-route bearer configuration.** Single middleware-wide setting in this
  iteration.

## References

- [PR design spec](superpowers/specs/2026-05-18-bearer-token-auth-design.md) — full design rationale, alternatives considered, and per-section sign-off history.
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) — Bearer Token Usage.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) — OAuth 2.0 Token Introspection.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) — JWT Profile for OAuth 2.0 Access Tokens.
