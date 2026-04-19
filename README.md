# Traefik OIDC Middleware

OpenID Connect authentication middleware for Traefik. Replaces forward-auth +
oauth2-proxy. Auto-detects all major OIDC providers, validates ID tokens,
manages sessions, and forwards user identity to downstream services.

## Documentation

- [Configuration reference](docs/CONFIGURATION.md) — every parameter
- [Provider guide](docs/PROVIDERS.md) — Google, Azure, Auth0, Okta, Keycloak, Cognito, GitLab, GitHub, generic
- [Auth0 audience guide](docs/AUTH0_AUDIENCE_GUIDE.md) — custom APIs, opaque tokens, token confusion
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
| `clientSecret` | OAuth 2.0 client secret. Supports `urn:k8s:secret:ns:name:key`. |
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
