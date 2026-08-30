# Configuration Reference

Complete reference for all Traefik OIDC middleware configuration options.

## Table of Contents

- [Required Parameters](#required-parameters)
- [Client Authentication](#client-authentication)
- [Optional Parameters](#optional-parameters)
- [Security Options](#security-options)
- [Session Management](#session-management)
- [Access Control](#access-control)
- [Headers Configuration](#headers-configuration)
- [Security Headers](#security-headers)
- [Scope Configuration](#scope-configuration)
- [Advanced Options](#advanced-options)

---

## Required Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `providerURL` | string | Base URL of the OIDC provider | `https://accounts.google.com` |
| `clientID` | string | OAuth 2.0 client identifier | `1234567890.apps.googleusercontent.com` |
| `clientSecret` | string | OAuth 2.0 client secret. Required when `clientAuthMethod` is unset, `client_secret_post`, or `client_secret_basic`. Optional when `clientAuthMethod: private_key_jwt`. | `your-client-secret` |
| `sessionEncryptionKey` | string | Key for encrypting session data (min 32 bytes) | `your-32-byte-encryption-key-here` |
| `callbackURL` | string | Path where provider redirects after authentication | `/oauth2/callback` |

### Basic Configuration Example

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: your-client-id.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: your-32-byte-encryption-key-here
      callbackURL: /oauth2/callback
```

---

## Client Authentication

The middleware supports three client authentication methods at the token and
revocation endpoints. The default is `client_secret_post` (current behavior);
`private_key_jwt` is opt-in and backwards compatible.

| Method | Default | Description |
|--------|---------|-------------|
| `client_secret_post` | yes | `client_id` + `client_secret` in the request body. |
| `client_secret_basic` | no | RFC 6749 §2.3.1 — `client_id` + `client_secret` in the `Authorization: Basic` header (form-urlencoded then base64); not in the body. |
| `private_key_jwt` | no | RFC 7523 §2.2 — plugin signs a short-lived JWT with a private key and sends it as `client_assertion`. |

Select via `clientAuthMethod`:

```yaml
clientAuthMethod: private_key_jwt
```

### client_secret_post

Default. The plugin sends `client_id` and `client_secret` as form parameters
in the token / revocation request body. No additional configuration required.

### private_key_jwt

Asymmetric client authentication per
[RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523). Use this when your
IdP enforces short secret TTLs, when policy mandates secretless clients, or
when you want to avoid distributing a shared secret to the proxy.

For each token / revocation request the plugin builds a JWS with:

- `iss` = `sub` = `clientID`
- `aud` = token endpoint URL
- `iat` = now, `exp` = now + 60s
- `jti` = random hex per request
- `kid` header = `clientAssertionKeyID`

**Required fields:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `clientAuthMethod` | string | `client_secret_post` | Set to `private_key_jwt`. |
| `clientAssertionPrivateKey` | string | none | Inline PEM private key. Mutually exclusive with `clientAssertionKeyPath`. PKCS#8, PKCS#1, and SEC1 formats accepted. |
| `clientAssertionKeyPath` | string | none | Path to PEM private key on disk. Mutually exclusive with `clientAssertionPrivateKey`. |
| `clientAssertionKeyID` | string | none | `kid` header inserted in the JWS. Must match the public key registered with the IdP. |
| `clientAssertionAlg` | string | `RS256` | One of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. |

When `clientAuthMethod: private_key_jwt`, `clientSecret` is optional.

**Example — inline PEM:**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth
spec:
  plugin:
    traefikoidc:
      providerURL: https://idp.example.com
      clientID: my-client-id
      sessionEncryptionKey: your-32-byte-encryption-key-here
      callbackURL: /oauth2/callback
      clientAuthMethod: private_key_jwt
      clientAssertionKeyID: key-2026-01
      clientAssertionAlg: RS256
      clientAssertionPrivateKey: |
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
        MZj4ev7QnMa1mYV3Kx1jRkH5YwXQ7N2J2j8K5pP6h0oZmXq1yQv4r8wZb3sH9D2k
        ... (truncated) ...
        -----END PRIVATE KEY-----
```

**Example — key on disk:**

```yaml
clientAuthMethod: private_key_jwt
clientAssertionKeyPath: /etc/traefik/oidc/client-key.pem
clientAssertionKeyID: key-2026-01
clientAssertionAlg: RS256
```

**Generating an RS256 key with OpenSSL:**

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out client-key.pem
openssl rsa -in client-key.pem -pubout -out client-pub.pem
```

Register `client-pub.pem` (or its JWK form) with your IdP under the same
`kid` you set in `clientAssertionKeyID`.

**Notes:**

- The private key is parsed once at plugin startup. Key rotation requires a
  Traefik reload.
- Assertion lifetime is fixed at 60 seconds.
- A fresh random `jti` is generated per request.
- The `aud` claim is the token endpoint URL (from discovery).
- Tracking issue:
  [#135](https://github.com/lukaszraczylo/traefikoidc/issues/135).

### client_secret_basic

Per [RFC 6749 §2.3.1][rfc6749-2-3-1], the plugin sends the client credentials
in an `Authorization: Basic` header instead of the body. Both halves
(`client_id`, `client_secret`) are form-urlencoded individually, joined with
a colon, then base64-encoded. Use this when your IdP requires Basic auth at
the token endpoint and rejects credentials in the body.

```yaml
clientAuthMethod: client_secret_basic
clientID: your-client-id
clientSecret: your-client-secret
```

[rfc6749-2-3-1]: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1

---

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logoutURL` | string | `callbackURL + "/logout"` | Path for logout requests |
| `postLogoutRedirectURI` | string | `/` | Redirect URL after logout |
| `logLevel` | string | `info` | Logging verbosity (`debug`, `info`, `error`) |
| `forceHTTPS` | bool | `true` | Force HTTPS for redirect URIs (set `false` only for plaintext HTTP local dev) |
| `rateLimit` | int | `100` | Maximum requests per second |
| `excludedURLs` | []string | none | Paths that bypass authentication, matched at a path-segment or file-extension boundary |
| `revocationURL` | string | auto-discovered | Token revocation endpoint. Takes precedence over the discovered value. |
| `oidcEndSessionURL` | string | auto-discovered | Provider's end session endpoint. Takes precedence over the discovered value. |
| `introspectionURL` | string | auto-discovered | RFC 7662 token introspection endpoint. Set this when your IdP omits `introspection_endpoint` from discovery. Takes precedence over the discovered value. |
| `enablePKCE` | bool | `false` | Enable PKCE for authorization code flow |
| `minimalHeaders` | bool | `false` | Reduce forwarded headers |
| `clientAuthMethod` | string | `client_secret_post` | Client authentication method at token/revocation endpoints. One of `client_secret_post`, `client_secret_basic`, `private_key_jwt`. See [Client Authentication](#client-authentication). |
| `clientAssertionPrivateKey` | string | none | Inline PEM private key for `private_key_jwt`. Mutually exclusive with `clientAssertionKeyPath`. PKCS#8 / PKCS#1 / SEC1. |
| `clientAssertionKeyPath` | string | none | Path to PEM private key on disk for `private_key_jwt`. Mutually exclusive with `clientAssertionPrivateKey`. |
| `clientAssertionKeyID` | string | none | `kid` header for `private_key_jwt` assertions. Required when `clientAuthMethod: private_key_jwt`. |
| `clientAssertionAlg` | string | `RS256` | Signing algorithm for `private_key_jwt`. One of `RS256/384/512`, `PS256/384/512`, `ES256/384/512`. |
| `extraAuthParams` | map | none | Extra query parameters appended to the authorization request (e.g. re-selective prompt). |
| `perSourceLoginRateLimit` | int | `0` (off) | Throttle OIDC auth events (callback + login initiation) per external client source, in auth events per minute. Internal/loopback sources are never throttled. |
| `stripAuthCookies` | bool | `false` | Strip OIDC session cookies from the hop to the backend (mitigates HTTP 431). |
| `enableBackchannelLogout` | bool | `false` | Enable OIDC back-channel logout (IdP-initiated, server-to-server). |
| `backchannelLogoutURL` | string | derived | Back-channel logout endpoint path. |
| `enableFrontchannelLogout` | bool | `false` | Enable OIDC front-channel logout (browser iframe logout). |
| `frontchannelLogoutURL` | string | derived | Front-channel logout endpoint path. |
| `caCertPath` / `caCertPEM` | string | none | Custom CA bundle for OIDC TLS verification (filesystem path, or inline PEM). Mutually exclusive with `insecureSkipVerify`. |
| `insecureSkipVerify` | bool | `false` | Disable TLS verification for the OIDC client (load balancer / mTLS edge). Emits a loud warning at startup. |

### TLS Termination at Load Balancer

`forceHTTPS` defaults to `true`, so redirect URIs always use `https://`. This is
the correct default behind any TLS-terminating load balancer (AWS ALB, Google
Cloud LB, Azure App Gateway) — `X-Forwarded-Proto` cannot be trusted (ALB may
overwrite it).

Set `forceHTTPS: false` only when you serve OIDC over plaintext HTTP (local
dev). Otherwise leave it at default.

### Streaming Endpoints (SSE and WebSocket)

The middleware automatically bypasses the OIDC redirect for two request kinds
that browsers cannot follow a 302 on:

| Bypass | Triggered by |
|--------|--------------|
| Server-Sent Events (SSE) | `Accept: text/event-stream` |
| WebSocket upgrade | `Upgrade: websocket` + `Connection: upgrade` (RFC 6455) |

These requests do **not** require any explicit configuration — they are
handled implicitly. However, the bypass is **not** unauthenticated:

- A valid, encrypted session cookie is required. Requests without one are
  rejected (the connection cannot proceed to the backend).
- The session cookie is sealed with `sessionEncryptionKey`, so the
  `authenticated` flag cannot be forged.
- Validation is cookie-only — no JWK fetch / signature verification — so
  streaming endpoints keep working when the OIDC provider is briefly
  unavailable.
- The user identifier from the session is forwarded as `X-Forwarded-User`
  (and `X-Auth-Request-User` unless `minimalHeaders: true`).

For browser clients, the user must complete the normal OIDC flow on a
regular HTTP page first; the resulting session cookie is then reused on the
SSE / WebSocket connection.

---

## Security Options

### Audience Validation

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `audience` | string | `clientID` | Expected audience for access token validation |
| `strictAudienceValidation` | bool | `false` | Reject sessions with audience mismatch |
| `allowOpaqueTokens` | bool | `false` | Enable opaque token support via RFC 7662 |
| `requireTokenIntrospection` | bool | `false` | Require introspection for opaque tokens |

#### Production Security Configuration

```yaml
audience: "https://my-api.example.com"
strictAudienceValidation: true
```

#### Opaque Token Support

```yaml
allowOpaqueTokens: true
requireTokenIntrospection: true
strictAudienceValidation: true
```

### Other Security Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `disableReplayDetection` | bool | `false` | Disable JTI-based replay attack detection |
| `allowPrivateIPAddresses` | bool | `false` | Allow private IPs in provider URLs |

### Bearer-token (M2M) authentication

Opt-in path that accepts `Authorization: Bearer <jwt>` instead of the cookie
session flow. M2M-only, default off, audience-mandatory. See
[docs/BEARER_AUTH.md](BEARER_AUTH.md) for the threat model and operational
guidance.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableBearerAuth` | bool | `false` | Master switch. Startup fails if true with empty `audience` or with `bearerIdentifierClaim=email`. |
| `bearerIdentifierClaim` | string | `"sub"` | JWT claim used as the principal identifier. `"email"` is rejected at startup. |
| `stripAuthorizationHeader` | bool | `true` | Strip `Authorization` from forwarded requests after successful bearer auth. |
| `bearerEmitWWWAuthenticate` | bool | `true` | Emit RFC 6750 `WWW-Authenticate: Bearer error="..."` hints on 401. |
| `bearerOverridesCookie` | bool | `false` | Cookie wins when both bearer and cookie are present (default). Set true for bearer-wins. |
| `maxTokenAgeSeconds` | int64 | `86400` | Upper bound on `iat` claim age (24h). 0 disables the check. |
| `maxIdentifierLength` | int | `256` | Length cap on the sanitised principal identifier. |
| `bearerFailureThreshold` | int | `20` | Consecutive 401s from one source IP that trip the throttle. |
| `bearerFailureWindowSeconds` | int | `60` | Rolling window for counting 401s. |
| `bearerFailurePenaltySeconds` | int | `60` | 429 + `Retry-After` duration after the threshold trips. |

---

## Session Management

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sessionMaxAge` | int | `86400` (24h) | Maximum session age in seconds |
| `refreshGracePeriodSeconds` | int | `60` | Seconds before expiry to attempt refresh |
| `maxRefreshTokenAgeSeconds` | int | `21600` | Heuristic max age (in seconds) of a stored refresh token. Once exceeded, requests treat the RT as expired up front (returns 401 to AJAX, triggers full re-auth on navigations) instead of grant-spamming the IdP with `invalid_grant` retries. IdPs do not advertise RT TTL on the wire, so this is intentionally a conservative heuristic — tune to match your provider. Set `0` to disable. Default `21600` (6h). |
| `cookieDomain` | string | auto-detected | Domain for session cookies |
| `cookiePrefix` | string | `_oidc_raczylo_` | Prefix for cookie names |

### Multi-Subdomain Setup

```yaml
cookieDomain: .example.com  # Share cookies across subdomains
```

### Multiple Middleware Instances

When running multiple middleware instances with different authorization requirements, use unique prefixes:

```yaml
# User authentication middleware
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-userauth
spec:
  plugin:
    traefikoidc:
      cookiePrefix: "_oidc_userauth_"
      sessionEncryptionKey: user-encryption-key-min-32-bytes
      # ... other config
---
# Admin authentication middleware
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-adminauth
spec:
  plugin:
    traefikoidc:
      cookiePrefix: "_oidc_adminauth_"
      sessionEncryptionKey: admin-encryption-key-min-32-bytes
      allowedUsers:
        - admin@example.com
      # ... other config
```

### Extended Session Duration

```yaml
sessionMaxAge: 604800  # 7 days
# Common values:
# 3600     - 1 hour (high security)
# 86400    - 1 day (default)
# 259200   - 3 days
# 604800   - 7 days
# 2592000  - 30 days
```

---

## Access Control

### User Restrictions

| Parameter | Type | Description |
|-----------|------|-------------|
| `allowedUserDomains` | []string | Restrict to specific email domains |
| `allowedUsers` | []string | Specific email addresses allowed |
| `allowedRolesAndGroups` | []string | Required roles or groups |
| `roleClaimName` | string | JWT claim for roles (default: `roles`) |
| `groupClaimName` | string | JWT claim for groups (default: `groups`) |
| `userIdentifierClaim` | string | Claim for user ID (default: `email`) |

### Domain Restriction

```yaml
allowedUserDomains:
  - company.com
  - subsidiary.com
```

### Specific User Access

```yaml
allowedUsers:
  - user@example.com
  - contractor@external.org
```

### Role-Based Access Control

```yaml
allowedRolesAndGroups:
  - admin
  - developer
roleClaimName: "https://myapp.com/roles"  # For namespaced claims (Auth0)
```

### Access Control Logic

- If only `allowedUsers` is set: Only specified emails can access
- If only `allowedUserDomains` is set: Only specified domains can access
- If both are set: Access granted if email is in `allowedUsers` OR domain is in `allowedUserDomains`
- If neither is set: Any authenticated user can access

### Users Without Email (Azure AD)

For Azure AD service accounts or users without email:

```yaml
userIdentifierClaim: sub  # Options: sub, oid, upn, preferred_username
allowedUsers:
  - "abc12345-6789-0abc-def0-123456789abc"  # User object ID
```

---

## Headers Configuration

### Default Headers

The middleware sets these headers for downstream services:

| Header | Description |
|--------|-------------|
| `X-Forwarded-User` | User's email address |
| `X-User-Groups` | Comma-separated user groups |
| `X-User-Roles` | Comma-separated user roles |
| `X-Auth-Request-Redirect` | Original request URI |
| `X-Auth-Request-User` | User's email address |
| `X-Auth-Request-Token` | User's ID token |

### Minimal Headers Mode

For "431 Request Header Fields Too Large" errors:

```yaml
minimalHeaders: true  # Only forwards X-Forwarded-User
```

### Custom Templated Headers

```yaml
headers:
  - name: "X-User-Email"
    value: "{{.Claims.email}}"
  - name: "X-User-ID"
    value: "{{.Claims.sub}}"
  - name: "Authorization"
    value: "Bearer {{.AccessToken}}"
  - name: "X-User-Roles"
    value: "{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}"
```

**Template Variables:**
- `{{.Claims.field}}` - ID token claims (only whitelisted fields; see below)
- `{{.AccessToken}}` - Raw access token
- `{{.IdToken}}` / `{{.IDToken}}` - Raw ID token (both spellings work)
- `{{.RefreshToken}}` - Raw refresh token

**Important — file provider only:** Traefik's file provider runs every dynamic
configuration file through Go templating before the plugin sees it, so plain
`{{ }}` fails there with `can't evaluate field AccessToken in type bool`.
Escape with a raw string: ``value: "{{`{{.Claims.email}}`}}"``. All other
providers (Kubernetes CRD, Docker labels, Consul, ...) pass the value through
untouched — use the plain form shown above. Do not use quadruple braces
(`{{{{ }}}}`); no configuration path collapses them, and template validation
rejects them (issues #149, #151).

**Validation and the claims whitelist.** Header templates are parsed and
validated when the middleware loads; an invalid or disallowed template stops the
middleware from starting (the route then returns Traefik's
`invalid handler type: <nil>`). To prevent a template from accidentally
forwarding raw tokens or sensitive claims, only a fixed set of claim fields may
be emitted — the standard OIDC claims plus common provider claims (`email`,
`name`, `given_name`, `family_name`, `preferred_username`, `sub`, `groups`,
`roles`, `internal_role`, `role`, `department`, `organization`, `realm_access`,
`resource_access`, `oid`, `tid`, `upn`, `hd`, `picture`, `locale`, `zoneinfo`,
`phone_number`, `email_verified`, `updated_at`; the authoritative list is
`safeClaimsFields` in `template_validation.go`). Rejected: rendering the whole
context (`{{.}}`, `{{$}}`) or the whole claims map (`{{.Claims}}`), any claim not
on the list, functions other than `get`/`default`, and `range`/`with` that do not
target a specific listed claim (e.g. `{{range .Claims}}` is rejected; `{{range
.Claims.groups}}` is allowed).

**`allowedClaims`** extends the whitelist for claims your provider issues that
are not built in:

```yaml
allowedClaims:
  - employee_id
  - cost_center
headers:
  - name: "X-Employee-Id"
    value: "{{.Claims.employee_id}}"
```

Listed names apply to both direct access (`{{.Claims.employee_id}}`) and
`get` (`{{get .Claims "employee_id"}}`). Subfields of a whitelisted map-valued
claim (e.g. `realm_access.roles`) are already accessible without listing them
individually.

---

## Security Headers

### Security Profiles

| Profile | Use Case | Security Level |
|---------|----------|----------------|
| `default` | Standard web apps | High |
| `strict` | Maximum security | Very High |
| `development` | Local development | Medium |
| `api` | API endpoints | High |
| `custom` | Custom requirements | Configurable |

### Basic Configuration

```yaml
securityHeaders:
  enabled: true
  profile: "default"
```

### API with CORS

```yaml
securityHeaders:
  enabled: true
  profile: "api"
  corsEnabled: true
  corsAllowedOrigins:
    - "https://your-frontend.com"
    - "https://*.example.com"
  corsAllowCredentials: true
```

### Custom Security Configuration

```yaml
securityHeaders:
  enabled: true
  profile: "custom"

  # Content Security Policy
  contentSecurityPolicy: "default-src 'self'; script-src 'self'"

  # HSTS
  strictTransportSecurity: true
  strictTransportSecurityMaxAge: 31536000
  strictTransportSecuritySubdomains: true
  strictTransportSecurityPreload: true

  # Frame and Content Protection
  frameOptions: "DENY"
  contentTypeOptions: "nosniff"
  xssProtection: "1; mode=block"
  referrerPolicy: "strict-origin-when-cross-origin"

  # CORS
  corsEnabled: true
  corsAllowedOrigins: ["https://app.example.com"]
  corsAllowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  corsAllowedHeaders: ["Authorization", "Content-Type"]
  corsAllowCredentials: true
  corsMaxAge: 86400

  # Custom Headers
  customHeaders:
    X-Custom-Header: "value"

  # Server Identification
  disableServerHeader: true
  disablePoweredByHeader: true
```

### CORS Origin Patterns

```yaml
corsAllowedOrigins:
  - "https://example.com"        # Exact match
  - "https://*.example.com"      # Subdomain wildcard
  - "http://localhost:*"         # Port wildcard (development)
```

---

## Scope Configuration

### Default Behavior (Append Mode)

```yaml
scopes:
  - roles
  - custom_scope
# Result: ["openid", "profile", "email", "roles", "custom_scope"]
```

### Override Mode

```yaml
overrideScopes: true
scopes:
  - openid
  - profile
  - custom_scope
# Result: ["openid", "profile", "custom_scope"]
```

---

## Advanced Options

### Dynamic Client Registration (RFC 7591)

Dynamic Client Registration allows the middleware to automatically register itself with the OIDC provider, eliminating the need to manually create client credentials.

**Basic Configuration (Single Instance):**

```yaml
dynamicClientRegistration:
  enabled: true
  initialAccessToken: "your-token"  # Optional, if provider requires it
  persistCredentials: true
  credentialsFile: "/tmp/oidc-credentials.json"
  clientMetadata:
    redirect_uris:
      - "https://your-app.com/oauth2/callback"
    client_name: "My Application"
    application_type: "web"
    grant_types:
      - "authorization_code"
      - "refresh_token"
```

**Multi-Replica Deployment (Kubernetes):**

For Kubernetes deployments with multiple replicas, use Redis storage to share credentials across all instances and prevent registration race conditions:

```yaml
dynamicClientRegistration:
  enabled: true
  persistCredentials: true
  storageBackend: "redis"  # Share credentials via Redis
  redisKeyPrefix: "myapp:dcr:"  # Optional custom prefix
  clientMetadata:
    redirect_uris:
      - "https://your-app.com/oauth2/callback"
    client_name: "My Application"

redis:
  enabled: true
  address: "redis:6379"
  cacheMode: "redis"
```

**Storage Backend Options:**

| Backend | Description | Use Case |
|---------|-------------|----------|
| `file` | Store credentials in local file | Single instance deployments |
| `redis` | Store credentials in Redis | Multi-replica Kubernetes deployments |
| `auto` | Use Redis if available, fallback to file | Flexible deployments (default) |

### Multi-Replica Deployment

Without Redis, disable replay detection:

```yaml
disableReplayDetection: true
```

With Redis (recommended):

```yaml
redis:
  enabled: true
  address: "redis:6379"
  cacheMode: "hybrid"
```

See [REDIS.md](REDIS.md) for complete Redis configuration.

---

## Kubernetes Secrets

Reference secrets instead of hardcoding sensitive values:

```yaml
providerURL: urn:k8s:secret:oidc-secret:ISSUER
clientID: urn:k8s:secret:oidc-secret:CLIENT_ID
clientSecret: urn:k8s:secret:oidc-secret:SECRET
```

Create the secret:

```bash
kubectl create secret generic oidc-secret \
  --from-literal=ISSUER=https://accounts.google.com \
  --from-literal=CLIENT_ID=your-client-id \
  --from-literal=SECRET=your-client-secret \
  -n traefik
```

---

## Environment Variable Naming

**Important:** Avoid using "API" as a substring in environment variable names when using `${VAR}` syntax in Traefik configuration. Traefik reserves `TRAEFIK_API_*` variables and the substring may cause conflicts.

```yaml
# Bad - may cause issues
sessionEncryptionKey: ${OIDC_SECRET_API}

# Good
sessionEncryptionKey: ${OIDC_SECRET_SVC}
```
