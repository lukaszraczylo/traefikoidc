# Traefik OIDC Middleware

OpenID Connect authentication middleware for Traefik. Replaces forward-auth +
oauth2-proxy. Auto-detects all major OIDC providers, validates ID tokens,
manages sessions, and forwards user identity to downstream services.

## Documentation

- [Configuration reference](docs/CONFIGURATION.md) — every parameter
- [Provider guide](docs/PROVIDERS.md) — Google, Azure, Auth0, Okta, Keycloak, Cognito, GitLab, GitHub, generic
- [Auth0 audience guide](docs/AUTH0_AUDIENCE_GUIDE.md) — custom APIs, opaque tokens, token confusion
- [Bearer-token (M2M) auth](docs/BEARER_AUTH.md) — opt-in `Authorization: Bearer` path, threat model
- [Redis cache](docs/REDIS.md) — multi-replica deployments
- [Dynamic Client Registration](docs/DCR.md) — RFC 7591
- [Development](docs/DEVELOPMENT.md) · [Testing](docs/TESTING.md)

## Provider support

| Provider | OIDC | Refresh | Auto-detected by |
|----------|------|---------|------------------|
| Google | Full | Yes | `accounts.google.com` |
| Azure AD | Full | Yes | `login.microsoftonline.com`, `sts.windows.net` |
| Auth0 | Full | Yes | `*.auth0.com` |
| Okta | Full | Yes | `*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com` |
| Keycloak | Full | Yes | host containing `keycloak`, or `/realms/` in path (covers KC <17 `/auth/realms/` and 17+ `/realms/`) |
| AWS Cognito | Full | Yes | `cognito-idp.*.amazonaws.com` |
| GitLab | Full | Yes | `gitlab.com` |
| GitHub | OAuth 2.0 only — no ID token, no refresh | No | `github.com` |
| Generic | Full | Yes | any RFC-compliant `.well-known/openid-configuration` |

> Authentication and claim extraction use the **ID token**. Ensure your
> provider includes required claims (email, roles, groups) in the ID token,
> not just the access token or UserInfo endpoint.

## Install

Enable the plugin in Traefik's static configuration:

```yaml
# traefik.yml
experimental:
  plugins:
    traefikoidc:
      moduleName: github.com/lukaszraczylo/traefikoidc
      version: v0.7.10
```

Then attach the middleware in your dynamic configuration (see
[Quickstart](#quickstart) below).

This middleware tracks the current Traefik helm chart release. If it fails to
load, update Traefik first.

### Verify release signatures

Release checksums are signed with [cosign](https://github.com/sigstore/cosign)
keyless signing:

```bash
cosign verify-blob \
  --certificate-identity-regexp "https://github.com/lukaszraczylo/traefikoidc/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "traefikoidc_v<version>_checksums.txt.sigstore.json" \
  traefikoidc_v<version>_checksums.txt
```

## Standalone binary (oidcgate)

If you don't run Traefik, `oidcgate` exposes the same middleware as a
forward-auth daemon for nginx, Caddy, Traefik ForwardAuth, HAProxy, and
Envoy. See [`docs/OIDCGATE.md`](docs/OIDCGATE.md).

```bash
go build -o oidcgate ./cmd/oidcgate
./oidcgate --config examples/oidcgate.yaml
```

## Quickstart

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: urn:k8s:secret:traefik-oidc:CLIENT_SECRET
      sessionEncryptionKey: urn:k8s:secret:traefik-oidc:SESSION_KEY
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      postLogoutRedirectURI: /
      # forceHTTPS defaults to true (secure-by-default). Only set false if you
      # serve OIDC over plaintext HTTP for local dev.
      allowedUserDomains: [company.com]
      allowedRolesAndGroups: [admin, developer]
      excludedURLs: [/health, /metrics]
```

More example configs in [`examples/`](examples/).

## Required parameters

| Parameter | Description |
|-----------|-------------|
| `providerURL` | Issuer URL (used for OIDC discovery). |
| `clientID` | OAuth 2.0 client ID. |
| `clientSecret` | OAuth 2.0 client secret. Supports `urn:k8s:secret:ns:name:key`. Required when `clientAuthMethod` is unset, `client_secret_post`, or `client_secret_basic`; optional with `private_key_jwt`. |
| `sessionEncryptionKey` | Cookie encryption key, **min 32 bytes**. |
| `callbackURL` | Callback path, e.g. `/oauth2/callback`. |

## Common optional parameters

Full reference in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `forceHTTPS` | `true` | Forces `https://` in redirect URIs. Leave at default behind any TLS-terminating LB (AWS ALB, GCP LB, Azure App Gateway). Set `false` only for plaintext HTTP local dev. |
| `logoutURL` | `callbackURL + "/logout"` | RP-initiated logout path. |
| `postLogoutRedirectURI` | `/` | Where to send users after logout. |
| `scopes` | appended to `openid profile email` | Extra OAuth scopes. Set `overrideScopes: true` to replace defaults. |
| `excludedURLs` | none | Prefix-matched paths that bypass auth. |
| `allowedUserDomains` | none | Restrict to email domains. |
| `allowedUsers` | none | Restrict to specific addresses (or claim values when `userIdentifierClaim != email`). |
| `allowedRolesAndGroups` | none | Require any of these roles/groups from ID-token claims. |
| `roleClaimName` / `groupClaimName` | `roles` / `groups` | For namespaced claims (Auth0). |
| `userIdentifierClaim` | `email` | Use `sub`, `oid`, `upn`, or `preferred_username` for users without email. |
| `enablePKCE` | `false` | PKCE on the auth code flow. |
| `cookieDomain` | auto | Set explicitly for multi-subdomain setups (`.example.com`). |
| `cookiePrefix` | `_oidc_raczylo_` | Unique prefix per middleware instance to isolate sessions. |
| `sessionMaxAge` | `86400` | Session lifetime in seconds. |
| `refreshGracePeriodSeconds` | `60` | Proactively refresh tokens this many seconds before expiry. |
| `maxRefreshTokenAgeSeconds` | `21600` | Heuristic max stored refresh-token lifetime (6h). Past this, the plugin treats the RT as expired without contacting the IdP — returns 401 to AJAX, full re-auth on navigations. Set `0` to disable. Tune to match your IdP's RT TTL. |
| `rateLimit` | `100` | Requests/sec. Min `10`. |
| `logLevel` | `info` | `debug`, `info`, `error`. |
| `audience` | `clientID` | Custom access-token audience (Auth0 custom APIs). |
| `strictAudienceValidation` | `false` | Reject mismatched audiences. **Set `true` in production.** |
| `allowOpaqueTokens` / `requireTokenIntrospection` | `false` | Accept opaque access tokens via RFC 7662. |
| `disableReplayDetection` | `false` | Disable JTI cache. Use Redis instead for multi-replica. |
| `allowPrivateIPAddresses` | `false` | Permit private-IP `providerURL` (internal Keycloak, etc.). |
| `minimalHeaders` | `false` | Reduce forwarded headers (mitigates HTTP 431). |
| `stripAuthCookies` | `false` | Strip OIDC cookies from backend hop (mitigates HTTP 431). |
| `caCertPath` / `caCertPEM` | none | Trust an internal CA for the provider's TLS. |
| `insecureSkipVerify` | `false` | **Local dev only.** Disables TLS verification, logs a security warning. |
| `clientAuthMethod` | `client_secret_post` | Client auth method. Set `private_key_jwt` for RFC 7523 JWT assertions (Entra ID, Okta, Auth0, Keycloak). See [Client authentication via private key JWT](#client-authentication-via-private-key-jwt). |
| `clientAssertionPrivateKey` | none | Inline PEM private key for `private_key_jwt`. Mutually exclusive with `clientAssertionKeyPath`. |
| `clientAssertionKeyPath` | none | File path to PEM private key for `private_key_jwt`. |
| `clientAssertionKeyID` | none | JWS `kid` header. Required when `clientAuthMethod=private_key_jwt`; must match the public key registered with the IdP. |
| `clientAssertionAlg` | `RS256` | JWS alg for `private_key_jwt`. Supported: `RS256/384/512`, `PS256/384/512`, `ES256/384/512`. |
| `enableBackchannelLogout` / `backchannelLogoutURL` | `false` / none | OIDC Back-Channel Logout (server-to-server). |
| `enableFrontchannelLogout` / `frontchannelLogoutURL` | `false` / none | OIDC Front-Channel Logout (iframe). |
| `redis` | disabled | See [docs/REDIS.md](docs/REDIS.md). |
| `dynamicClientRegistration` | disabled | See [docs/DCR.md](docs/DCR.md). |

## Production gotchas

### TLS termination at a load balancer

`forceHTTPS` defaults to `true`, so redirect URIs always use `https://`. This is
the right default behind AWS ALB, GCP LB, Azure App Gateway, or any LB that
terminates TLS — `X-Forwarded-Proto` is unreliable (ALB may overwrite it).

Only set `forceHTTPS: false` when you actually serve OIDC over plaintext HTTP
(local dev). See [issue #82](https://github.com/lukaszraczylo/traefikoidc/issues/82).

### Multi-replica deployments

Each replica keeps its own in-memory JTI cache → false positive "token replay
detected" when the same token hits different replicas. Two options:

1. Set `disableReplayDetection: true` (loses replay protection).
2. Enable Redis for shared state (recommended) — see [docs/REDIS.md](docs/REDIS.md).

For IdP-initiated logout (back/front-channel) in multi-replica setups, Redis is
**required** so a logout on one instance invalidates sessions on the others.

### Multiple middleware instances on the same host

Each instance must use a unique `cookiePrefix` **and** `sessionEncryptionKey`,
otherwise a session minted by one instance can grant access through another.
See [issue #87](https://github.com/lukaszraczylo/traefikoidc/issues/87).

### Bearer-token (M2M) authentication

Opt-in path for API clients that present `Authorization: Bearer <jwt>` instead
of logging in via the browser flow. Default off. When enabled, the middleware
validates the bearer JWT against the configured OIDC provider (signature,
issuer, audience, expiry) and forwards the request downstream with the
principal headers — no cookie session is created.

```yaml
enableBearerAuth: true
audience: https://api.example.com   # REQUIRED when bearer is enabled
# optional, defaults shown:
bearerIdentifierClaim: sub          # claim used as X-Forwarded-User
stripAuthorizationHeader: true      # drop the raw token before forwarding
bearerEmitWWWAuthenticate: true     # RFC 6750 hint on 401s
bearerOverridesCookie: false        # cookie wins when both are present (safer)
maxTokenAgeSeconds: 86400           # 24h cap on iat
bearerFailureThreshold: 20          # consecutive 401s/IP before 429 throttle
```

Hardening built in by default:

- **Audience required.** Startup fails if `enableBearerAuth=true` and
  `audience` is unset. Eliminates the "token issued for service B accepted
  by A" confusion vector.
- **ID tokens explicitly rejected.** Bearer is access-token-only. ID tokens
  (detected via `nonce`, `typ: at+jwt`, `token_use`, `scope`, or audience
  shape) return `401`.
- **`alg` and `kid` pinned at the entrypoint.** Asymmetric-only allowlist
  (`RS256/384/512`, `PS256/384/512`, `ES256/384/512`); `kid` length and
  charset capped — both checked **before** any JWKS fetch so attacker noise
  can't amplify into upstream calls.
- **Identifier sanitised.** Default identifier source is `sub`; `email` is
  rejected unless explicitly opted in (which the middleware still refuses to
  avoid the unverified-email spoofing footgun). Control characters, bidi-
  override codepoints, and the delimiters `, ; =` are all rejected before
  the value reaches `X-Forwarded-User`.
- **Multi-audience tokens require `azp`.** When `aud` is an array of more
  than one element, the token must carry `azp == clientID`.
- **`iat` upper-age bound.** Tokens older than `maxTokenAgeSeconds` are
  rejected even if `exp` is far in the future.
- **Per-IP 401 throttle.** After `bearerFailureThreshold` consecutive 401s
  from one source IP, further bearer requests from that IP are rejected
  with `429 Too Many Requests` + `Retry-After`.
- **Cookie-wins by default.** When both a session cookie and an
  `Authorization: Bearer` header arrive on the same request, the cookie path
  runs (safer against browser/extension/proxy bearer injection). Set
  `bearerOverridesCookie: true` for the AWS/GCP/Kubernetes convention.
- **Replay protection preserved.** The bearer path skips the JTI **Set**
  (so the same token can be reused) but the **Get** stays active —
  `RevokeToken` still terminates a bearer token immediately.
- **Excluded URLs strip Authorization.** When `enableBearerAuth=true`,
  excluded paths (e.g. `/health`, `/metrics`) get the `Authorization` header
  removed before forwarding so the token can't leak into public endpoint
  logs.
- **Optional real-time revocation.** Set `requireTokenIntrospection: true`
  to call RFC 7662 introspection on every cache miss; revoked tokens fail
  immediately. Introspection endpoint failures return `503` (distinguishes
  infra outage from credential rejection).

**Obtaining bearer tokens** — minting is the IdP's job, not the
middleware's. The canonical M2M flow is OAuth 2.0 `client_credentials`
(RFC 6749 §4.4); Google requires JWT bearer assertion (RFC 7523) instead.
Minimal Auth0-shape request:

```bash
curl -s -X POST https://issuer.example.com/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":    "client_credentials",
    "client_id":     "your-m2m-client-id",
    "client_secret": "your-m2m-client-secret",
    "audience":      "https://api.example.com",
    "scope":         "api:read api:write"
  }'
```

The `audience` you request from the IdP **must match** the `audience` you
configured on the middleware. Per-provider endpoints, parameter names, and
gotchas (Entra v2 endpoint, Cognito Resource Servers, Keycloak audience
mappers, Google's opaque-token quirk) are documented in
[docs/BEARER_AUTH.md](docs/BEARER_AUTH.md#obtaining-bearer-tokens-from-your-oidc-provider).

Full threat model, configuration matrix, and follow-up gaps in
[docs/BEARER_AUTH.md](docs/BEARER_AUTH.md).

### SSE and WebSocket endpoints

Browser clients cannot follow an OIDC `302` redirect on an SSE stream or a
WebSocket upgrade. The middleware handles this automatically:

- **SSE** (`Accept: text/event-stream`) and **WebSocket** (`Upgrade: websocket`)
  requests skip the OIDC redirect.
- They are **not** unauthenticated — a valid encrypted session cookie is
  required, otherwise the request is rejected. The session must already exist
  (i.e. the user logged in via a normal HTTP page first).
- `X-Forwarded-User` is forwarded from the session.
- Validation is cookie-only (no JWK fetch), so streaming keeps working during
  brief IdP outages.

No configuration needed — this is implicit behavior.

### HTTP 431 from backends

Either the ID token or the chunked OIDC cookies overflow your backend's header
buffer. Combine these as needed:

```yaml
minimalHeaders: true     # drop X-Auth-Request-Token et al.
stripAuthCookies: true   # strip _oidc_raczylo_* cookies on the backend hop
```

Cookies remain in the browser; only the Traefik→backend hop is affected. See
[#64](https://github.com/lukaszraczylo/traefikoidc/issues/64),
[#122](https://github.com/lukaszraczylo/traefikoidc/issues/122).

### Internal CA for the provider

If the provider's TLS cert is signed by a private CA (self-hosted GitLab,
internal Keycloak, ADFS):

```yaml
caCertPath: /etc/ssl/certs/internal-ca.pem
# or, inline:
caCertPEM: |
  -----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----
```

Both can be combined. An unparseable bundle fails the plugin at startup.
See [#125](https://github.com/lukaszraczylo/traefikoidc/issues/125).

### Client authentication via private key JWT

Use when your IdP enforces short-lived secrets or pushes secretless client auth
— Microsoft Entra ID / Azure AD, Okta, Auth0, Keycloak. Instead of sending a
static `clientSecret`, the plugin signs a short-lived JWT and submits it as
`client_assertion` per [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523).

Minimal config:

```yaml
clientAuthMethod: private_key_jwt
clientAssertionKeyPath: /etc/traefik/oidc/client-key.pem
clientAssertionKeyID: my-key-2026
# clientAssertionAlg: RS256   # default; or PS256/384/512, ES256/384/512
```

Or inline:

```yaml
clientAuthMethod: private_key_jwt
clientAssertionPrivateKey: |
  -----BEGIN PRIVATE KEY-----
  ...
  -----END PRIVATE KEY-----
clientAssertionKeyID: my-key-2026
```

Accepted PEM forms: PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`), SEC1
(`EC PRIVATE KEY`). The assertion uses `iss=sub=clientID`, `aud=tokenURL`, 60s
lifetime, random hex `jti` per request. Sent on `/token` (auth-code + refresh)
and `/revoke`. The `kid` must match the public key registered with the IdP.

`clientSecret` becomes optional with `private_key_jwt`. Existing
`client_secret_post` setups are unaffected. Keys are parsed once at startup —
rotation requires a Traefik reload.

See [issue #135](https://github.com/lukaszraczylo/traefikoidc/issues/135).

### Environment variable names containing `API`

Traefik reserves `TRAEFIK_API_*`. User vars whose name contains `API` (e.g.
`OIDC_ENCRYPTION_SECRET_API`) make the plugin fail with
`invalid handler type: <nil>`. Rename to anything without the literal `API`
substring. See [#98](https://github.com/lukaszraczylo/traefikoidc/issues/98).

## Templated headers

Forward identity to backends via Go templates over ID-token claims and tokens:

```yaml
headers:
  - name: X-User-Email
    value: "{{{{.Claims.email}}}}"
  - name: Authorization
    value: "Bearer {{{{.AccessToken}}}}"
  - name: X-User-Roles
    value: "{{{{range $i, $e := .Claims.roles}}}}{{{{if $i}}}},{{{{end}}}}{{{{$e}}}}{{{{end}}}}"
```

Available bindings: `.Claims.<field>`, `.AccessToken`, `.IdToken`,
`.RefreshToken`. Names are case-sensitive (`.Claims`, not `.claims`).

> **Escape with quadruple braces.** If you see
> `can't evaluate field AccessToken in type bool`, Traefik's YAML parser ate
> your `{{ }}`. The fix that actually works is `{{{{ }}}}` — the YAML pass
> turns it into `{{ }}` for the Go template engine. Other escaping tricks
> (literal blocks, single quotes) do not work reliably.

## Default downstream headers

When a request is authenticated, the middleware sets:

| Header | Notes |
|--------|-------|
| `X-Forwarded-User` | User's email (always). |
| `X-User-Groups` | Comma-separated. |
| `X-User-Roles` | Comma-separated. |
| `X-Auth-Request-User` | User's email. |
| `X-Auth-Request-Redirect` | Original request URI. |
| `X-Auth-Request-Token` | Full ID token — the largest header; suppressed by `minimalHeaders`. |

Plus security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
X-XSS-Protection, Referrer-Policy) controlled by the `securityHeaders`
section — see [docs/CONFIGURATION.md](docs/CONFIGURATION.md#security-headers).

## Common errors

| Symptom | Cause |
|---------|-------|
| `Token verification failed` | Wrong/unreachable `providerURL`, or clock skew. |
| `Session encryption key too short` | `sessionEncryptionKey` is < 32 bytes. |
| `No matching public key found` | JWKS endpoint down, or `kid` mismatch. |
| `Access denied: Your email domain is not allowed` | User's domain not in `allowedUserDomains`. |
| `Access denied: You do not have any of the allowed roles or groups` | Claims missing or not in `allowedRolesAndGroups`. |
| `can't evaluate field AccessToken in type bool` | Template not escaped — use `{{{{ }}}}`. |
| `tls: failed to verify certificate: x509: certificate signed by unknown authority` | Internal CA — set `caCertPath` / `caCertPEM`. |
| `invalid handler type: <nil>` | Env var name contains `API` — rename it. |
| `false positive replay detected` | Multi-replica without Redis — see [Multi-replica deployments](#multi-replica-deployments). |
| Google sessions expire after ~1h | Consent screen still in "Testing" mode. **Do not** add `offline_access` — Google rejects it; the middleware sets `access_type=offline` automatically. |

Provider-specific issues (Keycloak mappers, Azure AD group overage, Auth0
namespaced claims, Cognito regions, GitLab self-hosted) live in
[docs/PROVIDERS.md](docs/PROVIDERS.md).

Set `logLevel: debug` to surface detail.

## License

See [LICENSE](LICENSE).
