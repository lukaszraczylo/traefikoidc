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
| Identity claim | Resolved via existing `UserIdentifierClaim` config; fallback `sub` → `client_id`/`azp` |
| Identifier sanitisation | Reject any value containing control characters (`\r`, `\n`, `\0`, etc.) |
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

1. Length / format guards: `len(token) <= AccessTokenConfig.MaxLength`, exactly two dots, non-empty after trim.
2. `t.verifyToken(token, verifyOpts{skipReplayMarking: true})` — reuses signature, issuer, audience, expiration checks.
3. **Token-type guard** via `classifyToken(claims)`: reject if `aud == clientID` and no `scope`/`scp`. Require `scope`/`scp` or `token_use == "access"`.
4. **Optional introspection**: if `requireTokenIntrospection` is set, call `introspectToken`; reject if `active == false`; surface 503 on transport failure.
5. **Identifier resolution**: try `userIdentifierClaim` (if configured), then `sub`, then `client_id`, then `azp`. Empty/missing returns an error.
6. **Sanitisation**: reject identifiers containing any `unicode.IsControl` character.
7. Return `&principal{ Source: sourceBearer, … }`.

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
type verifyOpts struct { skipReplayMarking bool }
```

Both the type and field are unexported (internal-only knob). Cookie path: omits / defaults (current behaviour preserved). Bearer path: sets `skipReplayMarking: true`. The JTI-blacklist `Set` near `token_manager.go:108-143` is gated on this flag.

### 7.8 Config additions (modify `settings.go`)

```go
EnableBearerAuth           bool `json:"enableBearerAuth,omitempty"`
StripAuthorizationHeader   bool `json:"stripAuthorizationHeader,omitempty"`
BearerSuppressWWWAuthenticate bool `json:"bearerSuppressWWWAuthenticate,omitempty"`
```

Defaults:
- `EnableBearerAuth`: false.
- `StripAuthorizationHeader`: true (applied when bearer auth is enabled).
- `BearerSuppressWWWAuthenticate`: false (RFC 6750 hints on by default).

### 7.9 Startup validation (modify `main.go` `New()`)

- `EnableBearerAuth && Audience == ""` → fatal error.
- `EnableBearerAuth && !StrictAudienceValidation` → warning log; not a hard failure.

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
| Signature / issuer / aud / exp fail | 401 | `Unauthorized` | `Bearer error="invalid_token"` | reason from verifyToken |
| Detected as ID token | 401 | `Unauthorized` | `Bearer error="invalid_token"` | ID tokens not accepted on bearer path |
| Introspection `active=false` | 401 | `Unauthorized` | `Bearer error="invalid_token"` | token inactive at IdP |
| Introspection endpoint failure | 503 | `Service Unavailable` | (none) | introspection unavailable |
| Identifier claim missing | 401 | `Unauthorized` | `Bearer error="invalid_token"` | no identifier claim |
| Identifier contains control chars | 401 | `Unauthorized` | `Bearer error="invalid_token"` | invalid identifier characters |
| Roles/groups not allowed | 403 | `Access denied` | (none) | user not in allowedRolesAndGroups |

Responses never include token contents, never include the raw failure reason, and never set `Location` headers (API clients cannot follow redirects).

## 10. Edge Cases

1. **Both bearer header and cookie session present.** Bearer wins. Cookie ignored (not cleared). Documented.
2. **`Authorization: Basic …`.** Not bearer; cookie path runs as today.
3. **`Authorization: Bearer ` (trailing space, no value).** Empty after trim → 401.
4. **Mixed-case prefix (`bearer`, `BEARER`, `BeArEr`).** Case-insensitive prefix check; token value preserved verbatim.
5. **Multiple `Authorization` headers.** Use only the first (Go `http.Header.Get` default). Documented.
6. **Bearer during OIDC init wait.** Bearer requests also block on init: we need `issuerURL`, `audience`, JWKs ready. If init fails, bearer requests return 503 just like cookie requests.
7. **SSE / WebSocket bypass with bearer.** Bypass paths keep cookie-only behaviour. Operators who want bearer on streaming endpoints must remove SSE/WS bypass. Documented.
8. **Logout endpoint with bearer.** Logout runs before bearer detection. Treated as cookie-session logout; bearer token revocation requires IdP-side action.
9. **Excluded URLs with bearer.** Bypass excluded URLs as today; bearer ignored on excluded paths.
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
- **Cache-evict regression**: same token, evict `tokenCache`, replay → still 200 (verifies `skipReplayMarking`).

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
| Token confusion (ID token used as bearer) | Explicit ID-token rejection in `classifyToken` |
| Audience confusion (token for service B accepted by A) | `Audience` mandatory; verified via existing `VerifyJWTSignatureAndClaims` |
| Replay-via-blacklist false positive | `SkipReplayMarking` on bearer path |
| Revocation lag | Optional RFC 7662 introspection; documented as the strict-revocation mode |
| Identifier-driven header injection | `sanitizeIdentifier` rejects control characters; `net/http` rejects on wire too (defence in depth) |
| Token leakage downstream | `StripAuthorizationHeader=true` by default |
| Token in logs | All log paths log reasons, not raw tokens; existing `safeLogErrorf` patterns reused. Bearer auth success / failure events logged at debug with identifier + sub + aud but no token bytes — satisfies the auth-event audit requirement without leaking secrets. |
| `email` claim spoofing | Not applicable in M2M; identifier comes from `sub`/`client_id`, not `email`. If a future iteration adds human-user bearer, must add `email_verified` check. |
| Bypass on SSE / WS endpoints | Documented: SSE/WS bypass keeps cookie-only behaviour; bearer ignored. Operators choose to widen if needed. |
| Configuration drift (operator forgets audience) | Startup fails when `EnableBearerAuth=true && Audience==""`. |

## 14. Open Questions

None — all design decisions resolved during brainstorming. Implementation may surface incidental questions (e.g. exact clock-skew leeway in `jwt.Verify`); those are out of scope for this spec and handled in the implementation plan.

## 15. Implementation Plan Reference

To be produced by the `writing-plans` skill in a follow-up document at `docs/superpowers/plans/2026-05-18-bearer-token-auth-plan.md`. The plan decomposes this design into ordered, independently-testable PRs.
