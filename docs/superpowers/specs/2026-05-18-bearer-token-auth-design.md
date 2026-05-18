# Bearer Token Authentication — Design Spec

- **Date**: 2026-05-18
- **Status**: Design — pending implementation plan
- **Supersedes**: PR #93 (broken implementation; recommended to close in favour of this design)

## 1. Summary

Add an opt-in path that lets API clients (machine-to-machine) authenticate by presenting a signed access token in the `Authorization: Bearer <token>` header, bypassing the cookie-based OIDC redirect flow. Identity, roles, and authorization checks remain consistent with the existing cookie path; the only thing that changes is how the principal is established for that single request.

The feature is implemented by extracting a shared `forwardAuthorized` pipeline from the existing `processAuthorizedRequest`, introducing a `principal` value type, and adding a small bearer-specific entrypoint that builds a principal directly from a verified JWT — without synthesising a fake `SessionData`.

## 2. Motivation

PR #93 attempted this feature by building an in-memory `SessionData` from JWT claims and reusing `processAuthorizedRequest`. The approach has three latent defects:

1. The synthetic session omits `mainSession.Values["user_identifier"]`. `processAuthorizedRequest` reads it via `GetUserIdentifier()`; when empty it bails to `defaultInitiateAuthentication` and issues an OIDC redirect. The feature is non-functional in practice despite the unit test passing.
2. `verifyToken` accepts both ID tokens (audience match against `clientID`) and access tokens. ID tokens are not API credentials; treating them as such is a classic token-confusion vector.
3. `verifyToken` adds JTI to the replay blacklist on first verify. Once the verified-token cache evicts, subsequent reuse of the same bearer token triggers a false-positive replay rejection.

Rather than patch a synthetic-session approach that will keep generating bugs as `SessionData` evolves, this spec replaces it with a cleaner abstraction where session lifecycle and post-auth header injection live in separate units.

## 3. Goals

- Accept `Authorization: Bearer <jwt>` from M2M clients, validate the token, and forward the request downstream with identity headers populated.
- Enforce the same `allowedRolesAndGroups` policy as the cookie path.
- Default-off; safe defaults when enabled (audience required, ID tokens rejected, identifier sanitised).
- No behavioural change to the cookie path. Existing tests must continue to pass without modification.

## 4. Non-Goals

- Human-user / browser flows. Bearer is M2M-only in this iteration.
- Pure opaque access tokens on the bearer path. Tokens must be JWTs; introspection (RFC 7662) is supported *on top of* JWT verification for revocation state, not as a substitute for it.
- mTLS, API keys, or any other auth method. The `principal` abstraction enables them later, but they are not delivered here.
- Per-route bearer configuration. Single middleware-wide setting.

## 5. Decided Requirements

| Topic | Decision |
|---|---|
| Consumer type | Machine-to-machine (M2M) only |
| Token format | JWT only (signature, issuer, audience, exp) |
| Audience | Mandatory when feature enabled; startup fails if `Audience == ""` |
| Token type | Access tokens only; ID tokens explicitly rejected |
| Revocation | JWT-only verification by default; introspection (RFC 7662) opt-in via existing `RequireTokenIntrospection` |
| Identity claim | Resolved via existing `UserIdentifierClaim` config (must resolve to a non-empty string claim). `sub` is the default and is mandatory per `jwt.go:416` — the bearer path does NOT introduce a fallback chain because the existing JWT verifier rejects empty `sub`. If `UserIdentifierClaim` resolves to a different claim, the identifier becomes that value; `sub` must still be present and non-empty to pass verification. |
| Identifier sanitisation | Reject value containing any `unicode.IsControl` char, any Unicode bidi-override (U+202A–U+202E, U+2066–U+2069), leading/trailing whitespace, commas, semicolons, equals signs. Max length 256 bytes. |
| Token classifier | **Reuse existing `detectTokenType(jwt, token)` at `token_manager.go:187-303`** which already handles `nonce`, `typ: at+jwt`, `token_use`, `scope`, and aud-vs-clientID priority. Bearer path rejects any token where `detectTokenType == true` (ID token). Do not invent a parallel classifier. |
| Algorithm pinning | Hard-pin `alg ∈ {RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512}`, enforced **before** JWKS lookup on the bearer path. Prevents wasted JWKS fetches for `alg=none`/HS attacker probes. |
| `kid` hardening | `kid` ≤ 256 bytes, charset `[A-Za-z0-9._\-=]`. Reject before JWKS lookup. |
| Token age | Bearer path enforces `now - iat <= MaxTokenAgeSeconds` (default 86400 / 24h, configurable). Cookie path unchanged. |
| Multi-audience policy | If `aud` is an array (length > 1), require `azp` claim to be present and equal to `clientID`. Single-string `aud` unaffected. |
| Mixed bearer + cookie precedence | **Cookie wins by default** when both are presented (safer for browser scenarios). Operator opt-in: `BearerOverridesCookie=true` to flip. Either way, a warning is logged on the request. |
| Bearer + excluded URL | `Authorization` header is **stripped** before forwarding when the request hits an excluded URL. Prevents bearer leaking into public endpoints' downstream logs and prevents recon via excluded paths. |
| Per-source bearer 401 throttle | New sharded cache `failedBearerAttempts` keyed by client IP. After N (default 20) consecutive 401s from one IP within 1 minute, reject further bearer requests from that IP with 429 for 60s. Applied BEFORE `verifyToken` to deny JWKS amplification. |
| `Authorization` header passthrough | New `StripAuthorizationHeader` config, default `true` |
| Roles/groups gating | Same `allowedRolesAndGroups` rules as cookie path |
| Default state | `EnableBearerAuth` = `false` |
| JTI replay marking | Suppressed on bearer path; cookie path unchanged |
| Failure response shape | 401 with generic body; `WWW-Authenticate: Bearer error="invalid_token"` per RFC 6750 |
| Introspection endpoint outage | 503 (distinguishes infra outage from token rejection) |
| Mixed bearer + cookie | Bearer wins; cookie ignored on that request |
| SSE/WS bypass + bearer | Bypass paths keep cookie-only check; bearer header ignored on SSE/WS |

## 6. Architecture

```
                ┌──────────────────┐
   HTTP req ──► │   ServeHTTP      │  (existing entry; adds bearer detection)
                └─────────┬────────┘
              ┌───────────┴────────────┐
              ▼                        ▼
        cookie / session         bearer (Authorization: Bearer …)
              │                        │
              ▼                        ▼
    ┌────────────────┐        ┌────────────────────┐
    │ buildPrincipal │        │ buildPrincipal     │
    │ FromSession()  │        │ FromBearerToken()  │
    └────────┬───────┘        └─────────┬──────────┘
             │     produces *principal  │
             └──────────────┬───────────┘
                            ▼
              ┌────────────────────────────┐
              │ forwardAuthorized(rw,req,p)│  (shared pipeline)
              │  • roles/groups gate       │
              │  • header injection        │
              │  • header templates        │
              │  • security headers        │
              │  • cookie stripping        │
              │  • next.ServeHTTP          │
              └────────────────────────────┘
```

**Invariant**: `forwardAuthorized` never touches session storage. Session-specific concerns (Save, IsDirty, backchannel-logout invalidation) stay inside `processAuthorizedRequest` around the call to `forwardAuthorized`.

**Feature gate**: when `EnableBearerAuth == false`, the bearer-detection check in `ServeHTTP` is a no-op. Existing deployments observe byte-identical behaviour.

## 7. Components

### 7.1 `principal` type (new file `principal.go`)

```go
type principalSource int

const (
    sourceSession principalSource = iota
    sourceBearer
)

type principal struct {
    Identifier   string                 // drives X-Forwarded-User
    Email        string                 // optional, "" for M2M
    Subject      string                 // sub claim
    ClientID     string                 // azp / client_id, M2M caller
    Claims       map[string]interface{} // raw claims for templates / groups
    AccessToken  string                 // for X-Auth-Request-Token (gated by minimalHeaders)
    IDToken      string                 // "" on bearer path
    RefreshToken string                 // "" on bearer path
    Source       principalSource
}
```

Pure data. No methods that mutate it. No I/O. No manager pointer.

### 7.2 `buildPrincipalFromSession(*SessionData) *principal` (new in `principal.go`)

Read-only adapter over existing `SessionData` getters: `GetUserIdentifier`, `GetEmail`, `GetAccessToken`, `GetIDToken`, `GetRefreshToken`, cached claims via `GetIDTokenClaims`. Does not write back to the session. This is the only function that still knows about `SessionData`.

### 7.3 `buildPrincipalFromBearerToken(token string) (*principal, error)` (new in `bearer_auth.go`)

1. **Length / format guards**: `len(token) <= AccessTokenConfig.MaxLength`, exactly two dots, non-empty after trim.
2. **Parse header for early alg/kid pinning** (without trusting payload): decode JOSE header; reject if `alg` ∉ asymmetric allowlist; reject if `kid` missing, > 256 bytes, or contains chars outside `[A-Za-z0-9._\-=]`. This happens **before** JWKS lookup so attacker noise doesn't amplify into JWKS fetches.
3. **Per-IP 401 throttle check**: if this IP is in the `failedBearerAttempts` penalty box, return 429 immediately.
4. `t.verifyToken(token, verifyOpts{skipReplayMarking: true})` — reuses signature, issuer, audience, expiration, JTI Get (replay detection). The `skipReplayMarking` flag gates ONLY the JTI Set at `token_manager.go:108-143`; the JTI Get at `token_manager.go:44-47, 80-89` remains active so revoked tokens (via `RevokeToken` adding to blacklist) are still rejected.
5. **Re-parse claims** (`parseJWT(token)` is cheap and already done internally; reuse via a single decode if practical).
6. **Token-type guard**: call existing `detectTokenType(jwt, token)` (`token_manager.go:187-303`). Reject when it returns `true` (ID token). Belt-and-braces: also reject if `claims["nonce"]` is a non-empty string or `claims["token_use"] == "id"`.
7. **Multi-audience hardening**: if `claims["aud"]` is a `[]interface{}` with length > 1, require `claims["azp"]` to be a non-empty string equal to `t.clientID`; reject otherwise.
8. **`iat` upper-age bound**: reject when `time.Now().Unix() - int64(claims["iat"].(float64)) > MaxTokenAgeSeconds` (default 86400).
9. **Optional introspection**: if `requireTokenIntrospection` is set, call `introspectToken`; reject if `active == false` (401); surface 503 on transport failure. Bearer-path introspection cache TTL is capped at 60s (not 5min) to keep the "real-time revocation" promise close to true.
10. **Identifier resolution**: if `t.userIdentifierClaim` is configured, read that claim; otherwise read `sub`. The bearer path does NOT fall back to `client_id`/`azp` because `jwt.Verify` already enforces non-empty `sub` (`jwt.go:416-419`). Empty/missing identifier → 401.
11. **Identifier sanitisation**: trim, then reject if length > 256 OR contains any of: `unicode.IsControl`, bidi-override (U+202A–U+202E, U+2066–U+2069), `,`, `;`, `=`.
12. Return `&principal{ Source: sourceBearer, … }`.

On any failure path: increment the per-IP `failedBearerAttempts` counter; return the appropriate HTTP status (401 / 403 / 429 / 503) without revealing the failure reason in the response body. Reason is logged at debug only, with the identifier (if resolved) hashed via SHA-256 truncated to 8 hex chars.

### 7.4 `forwardAuthorized(rw, req, *principal)` (new in `middleware.go`, extracted)

The shared post-auth pipeline. Lifted verbatim from the existing `processAuthorizedRequest`:

1. Roles/groups extraction via existing `extractGroupsAndRolesFromClaims`.
2. `allowedRolesAndGroups` gate (existing logic).
3. Inject `X-Forwarded-User`, `X-User-Groups`, `X-User-Roles`.
4. Inject `X-Auth-Request-*` (gated by `minimalHeaders`).
5. Header templates.
6. Security headers.
7. Cookie strip when `stripAuthCookies`.
8. **New**: `Authorization` header strip when `stripAuthorizationHeader` AND `principal.Source == sourceBearer`.
9. `t.next.ServeHTTP(rw, req)`.

Does not call `Save`, does not check `IsDirty`. Session persistence stays with the cookie-path caller.

### 7.5 `handleBearerRequest(rw, req)` (new in `bearer_auth.go`)

```
1. Detect "Authorization: Bearer <token>" (case-insensitive prefix).
2. token = TrimSpace(authHeader[7:]); reject empty.
3. p, err := buildPrincipalFromBearerToken(token).
   On err → 401 with WWW-Authenticate, log reason at debug.
4. forwardAuthorized(rw, req, p).
```

Target: ~40 lines.

### 7.6 Refactor of `processAuthorizedRequest` (modify `middleware.go`)

Splits along the principal boundary:
- Session-specific part (backchannel-logout invalidation, `IsDirty` / `Save`) stays in `processAuthorizedRequest`.
- Everything else moves to `forwardAuthorized`.
- `processAuthorizedRequest` ends with `forwardAuthorized(rw, req, buildPrincipalFromSession(session))`.

### 7.7 `verifyOpts` extension to `verifyToken` (modify `token_manager.go`)

Add a parameter struct:
```go
type verifyOpts struct {
    skipReplayMarking bool // suppress JTI Set (token_manager.go:108-143); blacklist Get stays active
}
```

Both the type and field are unexported (internal-only knob). Signature change: `verifyToken(token string)` becomes `verifyToken(token string, opts verifyOpts)`. Existing callers pass `verifyOpts{}` (zero value = current behaviour). Bearer path passes `verifyOpts{skipReplayMarking: true}`.

**Critical semantics — must be reflected in implementation and tests:**
- `skipReplayMarking` only gates the **Set** at `token_manager.go:108-143` (the call adding the JTI to the blacklist and replay cache).
- The blacklist **Get** at `token_manager.go:44-47, 80-89` stays unconditionally active on the bearer path. Tokens revoked via `RevokeToken` (which adds the JTI to the blacklist) MUST still be rejected on the bearer path.
- Must NOT be implemented by mutating `t.disableReplayDetection` (struct field) — that would create a cross-request race that disables replay protection globally.

A targeted regression test exercises: bearer token verified once → admin calls `RevokeToken` adding the JTI to the blacklist → same token replayed → 401.

### 7.8 Config additions (modify `settings.go`)

```go
EnableBearerAuth              bool   `json:"enableBearerAuth,omitempty"`
StripAuthorizationHeader      bool   `json:"stripAuthorizationHeader,omitempty"`
BearerEmitWWWAuthenticate     bool   `json:"bearerEmitWWWAuthenticate,omitempty"`
BearerOverridesCookie         bool   `json:"bearerOverridesCookie,omitempty"`
MaxTokenAgeSeconds            int64  `json:"maxTokenAgeSeconds,omitempty"`
MaxIdentifierLength           int    `json:"maxIdentifierLength,omitempty"`
BearerFailureThreshold        int    `json:"bearerFailureThreshold,omitempty"`
BearerFailureWindowSeconds    int    `json:"bearerFailureWindowSeconds,omitempty"`
BearerFailurePenaltySeconds   int    `json:"bearerFailurePenaltySeconds,omitempty"`
```

Defaults (applied in `CreateConfig` for the bearer-related fields; values >0 only honoured when `EnableBearerAuth=true`):
- `EnableBearerAuth`: `false`.
- `StripAuthorizationHeader`: `true`.
- `BearerEmitWWWAuthenticate`: `true` (RFC 6750 hint enabled by default; flip to false if recon-exposure is a concern).
- `BearerOverridesCookie`: `false` (cookie wins when both present; flip to `true` for the legacy/industry-default behaviour).
- `MaxTokenAgeSeconds`: `86400` (24h upper bound on `iat`).
- `MaxIdentifierLength`: `256`.
- `BearerFailureThreshold`: `20` (consecutive 401s per IP before throttle).
- `BearerFailureWindowSeconds`: `60`.
- `BearerFailurePenaltySeconds`: `60` (429 reply for this long after threshold tripped).

### 7.9 Startup validation (modify `main.go` `New()`)

- `EnableBearerAuth && Audience == ""` → fatal error.
- `EnableBearerAuth && !StrictAudienceValidation` → warning log (recommended hardening).
- `EnableBearerAuth && UserIdentifierClaim == "email"` → fatal error (the bearer path is M2M and an `email` identifier without `email_verified` enforcement is a spoofing vector; M2M tokens should identify by `sub` or `client_id`-style claims).
- `EnableBearerAuth && MaxTokenAgeSeconds <= 0` → reset to default 86400 with info log.
- `EnableBearerAuth && BearerFailureThreshold <= 0` → reset to default 20 with info log.

## 8. Data Flow

### 8.1 Bearer path

```
ServeHTTP entry (pre-init paths unchanged: logout, backchannel, frontchannel, excluded URLs, SSE/WS bypass)
  │
  ├─ enableBearerAuth == false?  → fall through to cookie path
  │
  └─ enableBearerAuth == true AND Authorization starts with "Bearer "
       │
       ▼
  handleBearerRequest
       │
       ├─ format guards (empty, length, segment count)
       │
       ▼
  verifyToken(token, verifyOpts{SkipReplayMarking: true})
       │  signature, issuer, audience (strict), exp
       │
       ▼
  classifyToken(claims) → reject ID tokens
       │
       ▼
  if requireTokenIntrospection: introspectToken → active check
       │
       ▼
  resolveIdentifier(claims) → sanitiseIdentifier
       │
       ▼
  principal{Source: sourceBearer, …}
       │
       ▼
  forwardAuthorized(rw, req, principal)
       │
       ├─ roles/groups gate (403 on deny)
       ├─ header injection
       ├─ header templates
       ├─ security headers
       ├─ strip OIDC cookies (existing)
       ├─ strip Authorization header (new, when configured)
       └─ next.ServeHTTP(rw, req)
```

### 8.2 Cookie path (refactored, semantically unchanged)

```
processAuthorizedRequest
  1. Session validity / backchannel-logout invalidation (unchanged).
  2. principal := buildPrincipalFromSession(session).
  3. forwardAuthorized(rw, req, principal).
  4. if session.IsDirty(): session.Save().
```

## 9. Error Handling

| Trigger | Status | Body | WWW-Authenticate | Debug log reason |
|---|---|---|---|---|
| Empty bearer after prefix | 401 | `Unauthorized` | `Bearer error="invalid_request"` | empty bearer token |
| Token over MaxLength | 401 | `Unauthorized` | `Bearer error="invalid_token"` | token exceeds max length |
| Not a 3-segment JWT | 401 | `Unauthorized` | `Bearer error="invalid_token"` | malformed JWT |
| Disallowed `alg` (e.g. none, HS*) | 401 | `Unauthorized` | `Bearer error="invalid_token"` | unsupported alg |
| Missing/oversized/bad-charset `kid` | 401 | `Unauthorized` | `Bearer error="invalid_token"` | invalid kid |
| Signature / issuer / aud / exp fail | 401 | `Unauthorized` | `Bearer error="invalid_token"` | reason from verifyToken (category only) |
| `iat` older than MaxTokenAgeSeconds | 401 | `Unauthorized` | `Bearer error="invalid_token"` | token too old (iat outside age bound) |
| Multi-aud without matching `azp` | 401 | `Unauthorized` | `Bearer error="invalid_token"` | multi-aud token without azp match |
| Detected as ID token | 401 | `Unauthorized` | `Bearer error="invalid_token"` | ID tokens not accepted on bearer path |
| JTI blacklisted (revoked) | 401 | `Unauthorized` | `Bearer error="invalid_token"` | token JTI in blacklist |
| Introspection `active=false` | 401 | `Unauthorized` | `Bearer error="invalid_token"` | token inactive at IdP |
| Introspection endpoint failure | 503 | `Service Unavailable` | (none) | introspection unavailable |
| Identifier claim missing/empty | 401 | `Unauthorized` | `Bearer error="invalid_token"` | no identifier claim |
| Identifier fails sanitisation | 401 | `Unauthorized` | `Bearer error="invalid_token"` | invalid identifier characters |
| Per-IP failure threshold tripped | 429 | `Too Many Requests` | (none); `Retry-After: <BearerFailurePenaltySeconds>` | source IP in penalty box |
| Roles/groups not allowed | 403 | `Access denied` | (none) | user not in allowedRolesAndGroups |

Responses never include token contents, never include the raw failure reason, and never set `Location` headers (API clients cannot follow redirects).

## 10. Edge Cases

1. **Both bearer header and cookie session present.** Cookie wins by default (safer against browser/extension/proxy bearer injection). `BearerOverridesCookie=true` flips to bearer-wins. Either way: WARN log includes both source markers so operators can audit.
2. **`Authorization: Basic …`.** Not bearer; cookie path runs as today.
3. **`Authorization: Bearer ` (trailing space, no value).** Empty after trim → 401.
4. **Mixed-case prefix (`bearer`, `BEARER`, `BeArEr`).** Case-insensitive prefix check; token value preserved verbatim.
5. **Multiple `Authorization` headers.** Use only the first (Go `http.Header.Get` default). Documented.
6. **Bearer during OIDC init wait.** Bearer requests also block on init: we need `issuerURL`, `audience`, JWKs ready. If init fails, bearer requests return 503 just like cookie requests.
7. **SSE / WebSocket bypass with bearer.** Bypass paths keep cookie-only behaviour. Operators who want bearer on streaming endpoints must remove SSE/WS bypass. Documented.
8. **Logout endpoint with bearer.** Logout runs before bearer detection. Treated as cookie-session logout; bearer token revocation requires IdP-side action.
9. **Excluded URLs with bearer.** Bypass excluded URLs as today; bearer not validated on excluded paths. ADDITIONALLY: `Authorization: Bearer` is stripped from the request before forwarding so the token can't leak into the excluded endpoint's downstream logs / metrics scrapers / health checks.
10. **Concurrent identical bearer requests.** Existing `tokenCache` is concurrency-safe; no new locking.
11. **Client rotates token between requests.** Independent verification per token; independent cache entries.
12. **Clock skew.** Use existing `jwt.Verify` leeway. (If absent, add ±30s as a separate change; out of scope here.)

## 11. Testing Strategy

### 11.1 Integration tests (new `bearer_auth_test.go`)

Table-driven test against a real `httptest.Server` and the full `ServeHTTP` flow. Coverage matrix:

- Valid access token + allowed roles → 200, `next` ran, `X-Forwarded-User` set.
- Valid token without configured roles → 200.
- Wrong audience, expired, tampered signature → 401, `next` did not run.
- ID token presented → 401 (`ID tokens not accepted`).
- Malformed JWT (2 segments) → 401.
- Oversized token (> MaxLength) → 401.
- Empty bearer → 401.
- Missing identifier claim → 401.
- Identifier containing `\r\n` → 401.
- `allowedRolesAndGroups` mismatch → 403.
- `allowedRolesAndGroups` match → 200.
- `EnableBearerAuth=false` + bearer header → cookie path runs (302 to `/authorize`).
- Bearer + valid cookie session → bearer wins, 200.
- `StripAuthorizationHeader=true` → downstream sees no `Authorization`.
- `StripAuthorizationHeader=false` → downstream sees `Authorization`.
- Case variants (`bearer`, `BEARER`) → 200.
- SSE bypass + bearer → cookie-only check applies (bearer ignored).
- **Replay regression**: same token 1000 times in a row → all 200.
- **Cache-evict regression**: same token, force-evict `tokenCache` between iterations (call `tokenCache.Delete` directly), replay → still 200 (verifies `skipReplayMarking` doesn't poison the blacklist).
- **Revocation-while-bearer regression**: bearer token verified once → admin calls `RevokeToken` adding JTI to blacklist → same token presented → 401 (verifies blacklist Get stays active on bearer path even with `skipReplayMarking` set).
- **Alg-pin: token signed with `alg=none`** → 401, no JWKS fetch happens (verify with a counting mock).
- **`kid` injection: 50KB random kid** → 401 immediately, no JWKS fetch.
- **Per-IP throttle**: 21 bad bearer requests from same IP within 1 minute → 22nd returns 429 + Retry-After.
- **`iat` upper-age**: token with `iat = now - 25h` → 401 (older than 24h default).
- **Multi-aud without azp**: aud = `["a", "b"]`, no azp → 401.
- **Multi-aud with matching azp**: aud = `["api-aud", "other"]`, azp = clientID → 200.
- **Identifier with bidi-override**: sub contains U+202E → 401.
- **Identifier with comma**: sub = `"alice,bob"` → 401.
- **Identifier over 256 bytes** → 401.
- **`UserIdentifierClaim=email` at startup with EnableBearerAuth=true** → startup fails.
- **Excluded URL + bearer**: bearer header presented on excluded URL → request forwarded, downstream sees no `Authorization` header (stripped).

### 11.2 Unit tests (in `bearer_auth_test.go`)

- `classifyToken`: ID-token detection, access-token detection by `scope`/`scp`/`token_use`, ambiguous → reject.
- `resolveIdentifier`: precedence (`userIdentifierClaim` → `sub` → `client_id`/`azp`); missing → error; empty string → error.
- `sanitizeIdentifier`: rejects all `unicode.IsControl`; accepts email/sub-style values.

### 11.3 Introspection tests (`bearer_auth_introspection_test.go`)

- Token valid + introspection `active=true` → 200.
- Token valid + introspection `active=false` → 401.
- Introspection endpoint 500 → 503.
- Second request hits introspection cache (no second HTTP call).

### 11.4 Startup validation tests (extend `settings_test.go` / `main_test.go`)

- `EnableBearerAuth=true, Audience=""` → `New()` errors.
- `EnableBearerAuth=true, StrictAudienceValidation=false` → succeeds with warning.
- `EnableBearerAuth=false` → no validation; existing tests untouched.

### 11.5 Cookie-path regression suite

- All existing `TestServeHTTP_*` tests in `main_servehttp_test.go` pass unmodified.
- Add: cookie session, `EnableBearerAuth=true`, no bearer header → identical behaviour to baseline.
- Add: dirty session still triggers `Save()` after refactor.

### 11.6 Principal invariants

- `buildPrincipalFromSession`: `Source == sourceSession`; `IDToken` / `RefreshToken` populated when present in session.
- `buildPrincipalFromBearerToken`: `Source == sourceBearer`; `IDToken == ""`, `RefreshToken == ""`.
- `forwardAuthorized` produces identical headers for equivalent principals regardless of source.

### 11.7 Coverage gate

- New code in `bearer_auth.go` and `principal.go`: ≥ 90% line coverage.
- `forwardAuthorized` coverage ≥ existing `processAuthorizedRequest` coverage baseline.

### 11.8 Out of scope (follow-ups)

- Load test of bearer vs cookie hot path.
- Fuzzing the JWT parser.
- Additional auth methods (mTLS, API keys) — design enables them, but they are separate work.

## 12. Migration / Rollout

Default-off. Existing deployments observe no behavioural change. Operators opt in by setting:

```yaml
enableBearerAuth: true
audience: https://api.example.com   # required when bearer enabled
# optional:
stripAuthorizationHeader: true       # default
requireTokenIntrospection: false     # default; set true for real-time revocation
userIdentifierClaim: client_id       # optional override; defaults to sub fallback chain
```

Documentation: update `docs/CONFIGURATION.md` with a bearer-auth section, and add a new `docs/BEARER_AUTH.md` covering the security model, threat assumptions (token issuer is trusted; audience must be set; bearer means trust the issuer's revocation policy unless introspection enabled), and recommended configurations for common IdPs.

## 13. Security Considerations

| Concern | Mitigation |
|---|---|
| Token confusion (ID token used as bearer) | Reuse `detectTokenType` (`token_manager.go:187-303`) which checks `nonce`, `typ: at+jwt`, `token_use`, `scope`, aud-vs-clientID. Belt-and-braces: explicit `nonce` + `token_use == "id"` rejection on top. |
| Audience confusion (token for service B accepted by A) | `Audience` mandatory at startup; verified via existing `VerifyJWTSignatureAndClaims`; multi-aud tokens require matching `azp == clientID`. |
| Replay-via-blacklist false positive | `verifyOpts{skipReplayMarking: true}` on bearer path. Gates ONLY the Set; the Get stays so revoked tokens still fail. |
| Revocation lag | Optional RFC 7662 introspection. Bearer-path introspection cache TTL capped at 60s. Set `RequireTokenIntrospection=true` for real-time revocation. |
| `alg`-confusion / `alg=none` attacks | Hard-pin asymmetric allowlist at bearer entry, **before** JWKS fetch. Prevents wasted upstream calls and locks out HS/none probes. |
| `kid` injection / JWKS amplification | `kid` length cap (256 bytes) + charset allowlist enforced at bearer entry. |
| Bearer 401 brute-force / oracle | Per-IP `failedBearerAttempts` cache; configurable threshold + penalty box returning 429 + `Retry-After`. |
| `iat` clock-manipulation / forever-tokens | `MaxTokenAgeSeconds` upper bound (default 24h); cookie path unchanged. |
| Identifier-driven header injection | `sanitizeIdentifier`: length cap, control-char + bidi-override + `,;=` rejection. `net/http` rejects CRLF on the wire too (defence in depth). |
| Token leakage downstream | `StripAuthorizationHeader=true` by default. Also: `Authorization` stripped on excluded-URL requests so bearer can't leak into health/metrics downstream logs. |
| Token-in-logs | All log paths log reason categories, not raw tokens. Identifier hashed via SHA-256 truncated to 8 hex chars before any info/warn-level emission (full identifier only at debug). New `safeLogAuthEvent(category, hashedIdentifier, reasonCode)` helper makes this hard to misuse. |
| `email` claim spoofing | Startup fails if `EnableBearerAuth && UserIdentifierClaim == "email"`. Future human-user bearer iteration must add `email_verified` enforcement. |
| Bypass on SSE / WS endpoints | SSE/WS bypass keeps cookie-only behaviour; bearer ignored. Operators choose to widen if needed. |
| Mixed bearer + cookie precedence | Cookie wins by default (safer for browser scenarios); `BearerOverridesCookie=true` flips. WARN log on both-present requests. |
| Configuration drift (operator forgets audience) | Startup fails when `EnableBearerAuth=true && Audience==""`. |
| Downstream blast radius when `StripAuthorizationHeader=false` | Documented: forwarded bearer extends token's blast radius to all downstream services. Logs at those services become token stores. Operators must treat downstream log policy accordingly. |
| Introspection auth method (pre-existing gap, called out) | `token_introspection.go:80` uses `client_secret_basic` only; does not honour `private_key_jwt`. Out of scope for this PR but documented as a follow-up; operators using `ClientAuthMethod=private_key_jwt` + `RequireTokenIntrospection=true` should be aware introspection will use basic auth. |

## 14. Open Questions

None — all design decisions resolved during brainstorming + security review. Implementation may surface incidental questions (e.g. exact clock-skew leeway in `jwt.Verify`); those are out of scope for this spec and handled in the implementation plan.

## 14a. Security Review Reference

This design was reviewed by the `security-reviewer` subagent on 2026-05-18. Findings incorporated:

- **Critical**: C1 (classifier reuses `detectTokenType`), C2 (sub fallback dropped — unreachable due to `jwt.go:416`), C3 (replay-marking gates only Set, not Get; revocation regression test added).
- **High**: H1 (alg pinned at bearer entry), H2 (kid length + charset), H3 (cookie wins by default, configurable), H4 (per-IP 401 throttle), H5 (multi-aud requires azp).
- **Medium**: M1 (identifier max-length + bidi reject + delimiter chars), M2 (introspection cache TTL capped at 60s on bearer path), M4 (log-hashing via SHA-256[:8]), M5 (StripAuth blast-radius documented), M6 (iat upper-age bound), M7 (Authorization stripped on excluded URLs).
- **Low/Nit**: L2 (renamed to `BearerEmitWWWAuthenticate`), N3 (startup rejects `UserIdentifierClaim=email`).
- **Documented as pre-existing gaps (follow-up PRs)**: M3 (introspection auth method doesn't honour `private_key_jwt`).

## 15. Implementation Plan Reference

To be produced by the `writing-plans` skill in a follow-up document at `docs/superpowers/plans/2026-05-18-bearer-token-auth-plan.md`. The plan decomposes this design into ordered, independently-testable PRs.
