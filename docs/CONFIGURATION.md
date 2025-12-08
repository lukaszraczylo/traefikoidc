# Configuration Reference

Complete reference for all Traefik OIDC middleware configuration options.

## Table of Contents

- [Required Parameters](#required-parameters)
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
| `clientSecret` | string | OAuth 2.0 client secret | `your-client-secret` |
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

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logoutURL` | string | `callbackURL + "/logout"` | Path for logout requests |
| `postLogoutRedirectURI` | string | `/` | Redirect URL after logout |
| `logLevel` | string | `info` | Logging verbosity (`debug`, `info`, `error`) |
| `forceHTTPS` | bool | `false` | Force HTTPS for redirect URIs |
| `rateLimit` | int | `100` | Maximum requests per second |
| `excludedURLs` | []string | none | Paths that bypass authentication |
| `revocationURL` | string | auto-discovered | Token revocation endpoint |
| `oidcEndSessionURL` | string | auto-discovered | Provider's end session endpoint |
| `enablePKCE` | bool | `false` | Enable PKCE for authorization code flow |
| `minimalHeaders` | bool | `false` | Reduce forwarded headers |

### TLS Termination at Load Balancer

If running Traefik behind a load balancer (AWS ALB, Google Cloud LB, Azure App Gateway) that terminates TLS:

```yaml
forceHTTPS: true  # Required for correct redirect URIs
```

Without this setting, redirect URIs will use `http://` instead of `https://`, causing OAuth callback failures.

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

---

## Session Management

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sessionMaxAge` | int | `86400` (24h) | Maximum session age in seconds |
| `refreshGracePeriodSeconds` | int | `60` | Seconds before expiry to attempt refresh |
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
    value: "{{{{.Claims.email}}}}"
  - name: "X-User-ID"
    value: "{{{{.Claims.sub}}}}"
  - name: "Authorization"
    value: "Bearer {{{{.AccessToken}}}}"
  - name: "X-User-Roles"
    value: "{{{{range $i, $e := .Claims.roles}}}}{{{{if $i}}}},{{{{end}}}}{{{{$e}}}}{{{{end}}}}"
```

**Template Variables:**
- `{{.Claims.field}}` - ID token claims
- `{{.AccessToken}}` - Raw access token
- `{{.IdToken}}` - Raw ID token
- `{{.RefreshToken}}` - Raw refresh token

**Important:** Use double curly braces (`{{{{` and `}}}}`) to escape templates in YAML.

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

```yaml
dynamicClientRegistration:
  enabled: true
  initialAccessToken: "your-token"  # Optional
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
