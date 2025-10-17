# Traefik OIDC Middleware

This middleware replaces the need for forward-auth and oauth2-proxy when using Traefik as a reverse proxy to support OpenID Connect (OIDC) authentication.

## Overview

The Traefik OIDC middleware provides a complete OIDC authentication solution with these key features:

- **Universal provider support**: Works with 9+ OIDC providers including Google, Azure AD, Auth0, Okta, Keycloak, AWS Cognito, GitLab, and more
- **Automatic provider detection**: Automatically detects and configures provider-specific settings
- **Automatic scope filtering**: Intelligently filters OAuth scopes based on provider capabilities declared in OIDC discovery documents, preventing authentication failures with unsupported scopes
- **Security headers**: Comprehensive security headers with CORS, CSP, HSTS, and custom profiles
- **Domain restrictions**: Limit access to specific email domains or individual users
- **Role-based access control**: Restrict access based on roles and groups from OIDC claims
- **Session management**: Secure session handling with automatic token refresh
- **Rate limiting**: Protection against brute force attacks
- **Excluded paths**: Configure public URLs that bypass authentication
- **Custom headers**: Template-based headers using OIDC claims and tokens
- **Comprehensive logging**: Configurable log levels for debugging and monitoring

## Supported OIDC Providers

| Provider | Support Level | Refresh Tokens | Auto-Detection | Key Features |
|----------|---------------|----------------|---------------|--------------|
| **Google** | ✅ Full OIDC | ✅ Yes | ✅ `accounts.google.com` | Auto-config, Workspace support |
| **Azure AD** | ✅ Full OIDC | ✅ Yes | ✅ `login.microsoftonline.com` | Multi-tenant, group claims |
| **Auth0** | ✅ Full OIDC | ✅ Yes | ✅ `*.auth0.com` | Custom claims, flexible rules |
| **Okta** | ✅ Full OIDC | ✅ Yes | ✅ `*.okta.com` | Enterprise SSO, MFA support |
| **Keycloak** | ✅ Full OIDC | ✅ Yes | ✅ `/auth/realms/` path | Self-hosted, full customization |
| **AWS Cognito** | ✅ Full OIDC | ✅ Yes | ✅ `cognito-idp.*.amazonaws.com` | Managed service, regional |
| **GitLab** | ✅ Full OIDC | ✅ Yes | ✅ `gitlab.com` | Self-hosted support |
| **GitHub** | ⚠️ OAuth 2.0 Only | ❌ No | ✅ `github.com` | API access only, no claims |
| **Generic OIDC** | ✅ Full OIDC | ✅ Yes | ✅ Any endpoint | RFC-compliant providers |

### Provider Capabilities Matrix

| Feature | Google | Azure AD | Auth0 | Okta | Keycloak | Cognito | GitLab | GitHub | Generic |
|---------|--------|----------|-------|------|----------|---------|--------|--------|---------|
| **ID Tokens** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Refresh Tokens** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Auto-Configuration** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Custom Claims** | Limited | ✅ | ✅ | ✅ | ✅ | ✅ | Limited | ❌ | Varies |
| **Group/Role Claims** | Limited | ✅ | ✅ | ✅ | ✅ | ✅ | Limited | ❌ | Varies |
| **Domain Restriction** | ✅ (hd claim) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | Varies |
| **Self-Hosted** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Enterprise Features** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | Varies |

> **Important**: GitHub uses OAuth 2.0 (not OpenID Connect) and only provides access tokens. Use it for API access only, not for user authentication with claims. All other providers support full OIDC with ID tokens and user claims.

**Important Note on Token Validation:** This middleware performs authentication and claim extraction based on the **ID Token** provided by the OIDC provider. It does not primarily use the Access Token for these purposes (though the Access Token is available for templated headers if needed). Therefore, ensure that all necessary claims (e.g., email, roles, custom attributes) are included in the ID Token by your OIDC provider's configuration.

The middleware has been tested with Google, Azure AD, Auth0, Okta, Keycloak, AWS Cognito, GitLab, GitHub (OAuth 2.0), and other standard OIDC providers. It includes automatic provider detection and special handling for provider-specific requirements.

### Performance and Memory Management

This middleware includes advanced memory management features to ensure stable operation under high load:
- **Bounded caches**: All internal caches (metadata, sessions, tokens) have configurable size limits with LRU eviction
- **Automatic cleanup**: Background goroutines periodically clean up expired sessions and tokens
- **Memory monitoring**: Built-in memory leak detection and prevention
- **Graceful degradation**: Continues operating safely even under memory pressure
- **Zero goroutine leaks**: All background tasks are properly managed and terminated on shutdown

## Traefik Version Compatibility

This middleware follows closely the current Traefik helm chart versions. If the plugin fails to load, it's time to update to the latest version of the Traefik helm chart.

## Installation

### As a Traefik Plugin

1. Enable the plugin in your Traefik static configuration:

```yaml
# traefik.yml
experimental:
  plugins:
    traefikoidc:
      moduleName: github.com/lukaszraczylo/traefikoidc
      version: v0.7.10  # Use the latest version
```

2. Configure the middleware in your dynamic configuration (see examples below).

### Local Development with Docker Compose

For local development or testing, you can use the provided Docker Compose setup:

```bash
cd docker
docker-compose up -d
```

This will start Traefik with the OIDC middleware and two test services.

## Configuration Options

The middleware supports the following configuration options:

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `providerURL` | The base URL of the OIDC provider | `https://accounts.google.com` |
| `clientID` | The OAuth 2.0 client identifier | `1234567890.apps.googleusercontent.com` |
| `clientSecret` | The OAuth 2.0 client secret | `your-client-secret` |
| `sessionEncryptionKey` | Key used to encrypt session data (must be at least 32 bytes long) | `potato-secret-is-at-least-32-bytes-long` |
| `callbackURL` | The path where the OIDC provider will redirect after authentication | `/oauth2/callback` |

### Optional Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `logoutURL` | The path for handling logout requests | `callbackURL + "/logout"` | `/oauth2/logout` |
| `postLogoutRedirectURI` | The URL to redirect to after logout | `/` | `/logged-out-page` |
| `scopes` | OAuth 2.0 scopes to use for authentication | `["openid", "profile", "email"]` (always included by default) | `["roles", "custom_scope"]` (appended to defaults) |
| `overrideScopes` | When true, replaces default scopes with provided scopes instead of appending | `false` | `true` (use only the scopes explicitly provided) |
| `logLevel` | Sets the logging verbosity | `info` | `debug`, `info`, `error` |
| `forceHTTPS` | Forces HTTPS scheme for redirect URIs (**REQUIRED** for TLS termination at load balancer like AWS ALB) | `false` (when not specified) | `true`, `false` |
| `rateLimit` | Sets the maximum number of requests per second | `100` | `500` |
| `excludedURLs` | Lists paths that bypass authentication | none | `["/health", "/metrics", "/public"]` |
| `allowedUserDomains` | Restricts access to specific email domains | none | `["company.com", "subsidiary.com"]` |
| `allowedUsers` | A list of specific email addresses that are allowed access | none | `["user1@example.com", "user2@another.org"]` |
| `allowedRolesAndGroups` | Restricts access to users with specific roles or groups | none | `["admin", "developer"]` |
| `revocationURL` | The endpoint for revoking tokens | auto-discovered | `https://accounts.google.com/revoke` |
| `oidcEndSessionURL` | The provider's end session endpoint | auto-discovered | `https://accounts.google.com/logout` |
| `enablePKCE` | Enables PKCE (Proof Key for Code Exchange) for authorization code flow | `false` | `true`, `false` |
| `refreshGracePeriodSeconds` | Seconds before token expiry to attempt proactive refresh | `60` | `120` |
| `cookieDomain` | Explicit domain for session cookies (important for multi-subdomain setups) | auto-detected | `.example.com`, `app.example.com` |
| `audience` | Custom audience for access token validation (for Auth0 custom APIs, etc.) | `clientID` | `https://my-api.example.com` |
| `strictAudienceValidation` | Reject sessions with access token audience mismatch (prevents token confusion attacks) | `false` | `true` |
| `allowOpaqueTokens` | Enable opaque (non-JWT) access token support via RFC 7662 introspection | `false` | `true` |
| `requireTokenIntrospection` | Require introspection for opaque tokens (force validation, no fallback) | `false` | `true` |
| `headers` | Custom HTTP headers with templates that can access OIDC claims and tokens | none | See "Templated Headers" section |
| `securityHeaders` | Configure security headers including CSP, HSTS, CORS, and custom headers | enabled with default profile | See "Security Headers Configuration" section |
| `disableReplayDetection` | Disable JTI-based replay attack detection for multi-replica deployments | `false` | `true` |

> **⚠️ IMPORTANT - TLS Termination at Load Balancer:**
>
> If you're running Traefik behind a load balancer (AWS ALB, Google Cloud Load Balancer, Azure Application Gateway, etc.) that terminates TLS:
> - **You MUST set `forceHTTPS: true`** in your configuration
> - Without this setting, redirect URIs will use `http://` instead of `https://`, causing OAuth callback failures
> - This is especially critical for AWS ALB which may overwrite the `X-Forwarded-Proto` header
>
> **Default behavior:**
> - When `forceHTTPS` is **not specified** in your config → defaults to `false` (Go zero value)
> - When `forceHTTPS: true` is explicitly set → always uses `https://` for redirect URIs
> - When `forceHTTPS: false` is explicitly set → scheme detection based on headers/TLS
>
> See [GitHub Issue #82](https://github.com/lukaszraczylo/traefikoidc/issues/82) for details.

## Scope Configuration

### Scope Behavior

The middleware supports two modes for handling OAuth 2.0 scopes, controlled by the `overrideScopes` parameter:

#### Default Append Mode (`overrideScopes: false`)

By default, the middleware uses an **append** behavior for OAuth 2.0 scopes:

- **Default scopes** are always included: `["openid", "profile", "email"]`
- **User-provided scopes** are appended to the defaults with automatic deduplication
- The final scope list maintains the order: defaults first, then user scopes

#### Override Mode (`overrideScopes: true`)

When `overrideScopes` is set to `true`, the middleware uses **replacement** behavior:

- Default scopes are **not** automatically included
- Only the scopes explicitly provided in the `scopes` field are used
- You must include all required scopes explicitly, including `openid` if needed

### Examples:

**Default behavior (no custom scopes):**
```yaml
# No scopes field specified
# Result: ["openid", "profile", "email"]
```

**Default append behavior:**
```yaml
scopes:
  - roles
  - custom_scope
# Result: ["openid", "profile", "email", "roles", "custom_scope"]
```

**Overlapping scopes with append (automatic deduplication):**
```yaml
scopes:
  - openid      # Duplicate - will be deduplicated
  - roles
  - profile     # Duplicate - will be deduplicated
  - permissions
# Result: ["openid", "profile", "email", "roles", "permissions"]
```

**Using override mode:**
```yaml
overrideScopes: true
scopes:
  - openid
  - profile
  - custom_scope
# Result: ["openid", "profile", "custom_scope"]
```

**Empty scopes list with default behavior:**
```yaml
scopes: []
# Result: ["openid", "profile", "email"]
```

**Empty scopes list with override mode:**
```yaml
overrideScopes: true
scopes: []
# Result: [] (Warning: empty scopes may cause authentication to fail)
```

The default append behavior ensures essential OIDC scopes are always present, while the override mode gives you complete control over the exact scopes requested from the provider.

## Auth0 Audience Validation & Security

The middleware provides comprehensive support for Auth0 audience validation to prevent token confusion attacks. Auth0 can issue tokens in three different scenarios, each requiring specific configuration.

### Understanding Token Audiences

Per OAuth 2.0 and OIDC specifications:
- **ID Tokens**: MUST have `aud = client_id` (OIDC Core 1.0 spec)
- **Access Tokens**: Can have custom audiences (e.g., API identifiers)

Proper audience validation prevents **token confusion attacks** where a token intended for one API is used to access another API.

### Auth0 Scenarios

#### Scenario 1: Custom API Audience ✅ (RECOMMENDED)

**Configuration:**
```yaml
audience: "https://my-api.example.com"  # Your API identifier from Auth0
strictAudienceValidation: true          # Enforce strict validation
```

**Result**: Fully secure, OIDC compliant with proper access token audience validation.

#### Scenario 2: Default Audience ⚠️ (USE WITH CAUTION)

**Configuration:**
```yaml
# audience not specified (defaults to client_id)
strictAudienceValidation: true  # Recommended: reject mismatched tokens
```

**Behavior**: Access tokens may not contain client_id in audience, triggering security warnings. Set `strictAudienceValidation: true` to reject such sessions.

#### Scenario 3: Opaque Access Tokens ✅ (SUPPORTED)

**Configuration:**
```yaml
allowOpaqueTokens: true              # Enable opaque token support
requireTokenIntrospection: true      # Require introspection (recommended)
```

**Result**: Secure with OAuth 2.0 Token Introspection (RFC 7662).

### Security Configuration Options

| Option | Purpose | Recommended Value |
|--------|---------|-------------------|
| `audience` | Expected audience for access tokens | Your API identifier or leave empty |
| `strictAudienceValidation` | Reject sessions with audience mismatch | `true` for production |
| `allowOpaqueTokens` | Accept non-JWT access tokens | `true` if provider issues opaque tokens |
| `requireTokenIntrospection` | Force introspection for opaque tokens | `true` when `allowOpaqueTokens=true` |

### Complete Auth0 Configuration Examples

**Production Configuration (Scenario 1):**
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth0-secure
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-auth0-domain.auth0.com
      clientID: your-auth0-client-id
      clientSecret: your-auth0-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      audience: "https://my-api.example.com"
      strictAudienceValidation: true
      allowedRolesAndGroups:
        - "https://your-app.com/roles:admin"
        - editor
```

**Opaque Token Configuration (Scenario 3):**
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth0-opaque
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-auth0-domain.auth0.com
      clientID: your-auth0-client-id
      clientSecret: your-auth0-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      allowOpaqueTokens: true
      requireTokenIntrospection: true
      strictAudienceValidation: true
```

For detailed Auth0 configuration including all three scenarios, troubleshooting, and security best practices, see **[AUTH0_AUDIENCE_GUIDE.md](docs/AUTH0_AUDIENCE_GUIDE.md)**.

## Security Headers Configuration

The middleware includes comprehensive security headers support to protect your applications against common web vulnerabilities. Security headers are applied to all authenticated responses.

### Security Features

- **Content Security Policy (CSP)** - Prevents XSS and code injection
- **HTTP Strict Transport Security (HSTS)** - Forces HTTPS connections
- **Frame Options** - Protects against clickjacking attacks
- **XSS Protection** - Browser-level XSS filtering
- **Content Type Options** - Prevents MIME type sniffing
- **Referrer Policy** - Controls referrer information sharing
- **CORS Headers** - Complete Cross-Origin Resource Sharing support
- **Custom Headers** - Add any additional security headers

### Security Profiles

Choose from predefined security profiles or create custom configurations:

| Profile | Use Case | Security Level | CORS Enabled |
|---------|----------|----------------|--------------|
| `default` | Standard web applications | High | Disabled |
| `strict` | Maximum security applications | Very High | Disabled |
| `development` | Local development | Medium | Enabled (localhost) |
| `api` | API endpoints | High | Configurable |
| `custom` | Custom requirements | Configurable | Configurable |

### Configuration Examples

#### Default Security (Recommended)
```yaml
securityHeaders:
  enabled: true
  profile: "default"
```

#### Strict Security
```yaml
securityHeaders:
  enabled: true
  profile: "strict"
```

#### API with CORS
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

#### Custom Configuration
```yaml
securityHeaders:
  enabled: true
  profile: "custom"
  
  # Content Security Policy
  contentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
  
  # HSTS Settings
  strictTransportSecurity: true
  strictTransportSecurityMaxAge: 31536000  # 1 year
  strictTransportSecuritySubdomains: true
  strictTransportSecurityPreload: true
  
  # Frame and Content Protection
  frameOptions: "DENY"
  contentTypeOptions: "nosniff"
  xssProtection: "1; mode=block"
  referrerPolicy: "strict-origin-when-cross-origin"
  
  # CORS Configuration
  corsEnabled: true
  corsAllowedOrigins: ["https://app.example.com"]
  corsAllowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  corsAllowedHeaders: ["Authorization", "Content-Type", "X-Requested-With"]
  corsAllowCredentials: true
  corsMaxAge: 86400
  
  # Custom Headers
  customHeaders:
    X-Custom-Header: "custom-value"
    X-API-Version: "v1"
  
  # Server Identification
  disableServerHeader: true
  disablePoweredByHeader: true
```

### Security Headers Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `enabled` | Enable/disable security headers | `true` | `true`, `false` |
| `profile` | Security profile to use | `default` | `default`, `strict`, `development`, `api`, `custom` |
| `contentSecurityPolicy` | CSP header value | Profile-based | `"default-src 'self'"` |
| `strictTransportSecurity` | Enable HSTS | `true` | `true`, `false` |
| `strictTransportSecurityMaxAge` | HSTS max age in seconds | `31536000` | `86400` |
| `strictTransportSecuritySubdomains` | Include subdomains in HSTS | `true` | `true`, `false` |
| `strictTransportSecurityPreload` | Enable HSTS preload | `true` | `true`, `false` |
| `frameOptions` | X-Frame-Options header | `DENY` | `DENY`, `SAMEORIGIN`, `ALLOW-FROM uri` |
| `contentTypeOptions` | X-Content-Type-Options header | `nosniff` | `nosniff` |
| `xssProtection` | X-XSS-Protection header | `1; mode=block` | `1; mode=block` |
| `referrerPolicy` | Referrer-Policy header | `strict-origin-when-cross-origin` | `no-referrer` |
| `corsEnabled` | Enable CORS headers | `false` | `true`, `false` |
| `corsAllowedOrigins` | Allowed CORS origins | `[]` | `["https://app.com", "https://*.example.com"]` |
| `corsAllowedMethods` | Allowed CORS methods | `["GET", "POST", "OPTIONS"]` | `["GET", "POST", "PUT", "DELETE"]` |
| `corsAllowedHeaders` | Allowed CORS headers | `["Authorization", "Content-Type"]` | `["X-Custom-Header"]` |
| `corsAllowCredentials` | Allow credentials in CORS | `false` | `true`, `false` |
| `corsMaxAge` | CORS preflight cache time | `86400` | `3600` |
| `customHeaders` | Additional custom headers | `{}` | `{"X-Custom": "value"}` |
| `disableServerHeader` | Remove Server header | `true` | `true`, `false` |
| `disablePoweredByHeader` | Remove X-Powered-By header | `true` | `true`, `false` |
| `permissionsPolicy` | Permissions-Policy header | `` | `"geolocation=(), camera=(), microphone=()"` |
| `crossOriginEmbedderPolicy` | Cross-Origin-Embedder-Policy header | `` | `"require-corp"`, `"credentialless"`, `"unsafe-none"` |
| `crossOriginOpenerPolicy` | Cross-Origin-Opener-Policy header | `` | `"same-origin"`, `"same-origin-allow-popups"`, `"unsafe-none"` |
| `crossOriginResourcePolicy` | Cross-Origin-Resource-Policy header | `` | `"same-origin"`, `"same-site"`, `"cross-origin"` |

### CORS Wildcard Support

The middleware supports flexible CORS origin patterns:

```yaml
corsAllowedOrigins:
  - "https://example.com"              # Exact match
  - "https://*.example.com"            # Subdomain wildcard
  - "http://localhost:*"               # Port wildcard (development)
  - "*"                                # Allow all (not recommended)
```

## Advanced Configuration

The middleware provides several advanced configuration options for production environments.

### Provider-Specific Optimizations

The middleware automatically optimizes for each OIDC provider:
- **Google**: Automatically configures `access_type=offline` and `prompt=consent` for refresh tokens
- **Azure AD**: Optimized multi-tenant support and group claim handling
- **Auth0**: Enhanced custom claim processing and namespace support
- **Keycloak**: Self-hosted deployment optimizations
- **AWS Cognito**: Regional endpoint handling and user pool integration

### Token Management

- **Automatic token refresh**: Proactively refreshes tokens before expiration
- **Token validation**: Comprehensive JWT validation with security checks
- **Grace period**: Configurable time window for token refresh
- **Session handling**: Secure session management with encrypted storage

### Configuration Examples

#### High-Throughput Configuration
```yaml
# Optimized for high-traffic environments
rateLimit: 1000
refreshGracePeriodSeconds: 300
securityHeaders:
  enabled: true
  profile: "api"
  corsEnabled: true
  corsMaxAge: 86400
```

#### High-Security Configuration
```yaml
# Maximum security for sensitive environments
rateLimit: 50
allowedUserDomains: ["company.com"]
allowedRolesAndGroups: ["admin", "developer"]
securityHeaders:
  enabled: true
  profile: "strict"
  corsEnabled: false
```

#### Development Configuration
```yaml
# Development-friendly settings
logLevel: "debug"
forceHTTPS: false
securityHeaders:
  enabled: true
  profile: "development"
  corsEnabled: true
  corsAllowedOrigins: ["http://localhost:*"]
```

### Multi-Replica Deployment Configuration

When running multiple Traefik replicas with the OIDC plugin, you may encounter false positive replay detection errors. Each replica maintains its own in-memory JTI (JWT Token ID) cache, causing legitimate token reuse to be flagged as replay attacks.

**Problem**: When the same valid token hits different replicas:
- Request → Replica A → JTI added to Replica A's cache ✓
- Request → Replica B → JTI NOT in Replica B's cache ✓
- Request → Replica A → ❌ **FALSE POSITIVE**: "token replay detected"

**Solution**: Disable replay detection for distributed deployments:

```yaml
disableReplayDetection: true  # Disable JTI replay detection for multi-replica setups
```

**Security Note**: When `disableReplayDetection: true`:
- ✅ Token signatures still validated
- ✅ Expiration still checked
- ✅ All other claims still verified
- ❌ JTI replay check **skipped**

**Example Configuration**:
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-multi-replica
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: your-client-id
      clientSecret: your-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      disableReplayDetection: true  # Required for multi-replica deployments
```

**Recommendation**: For single-instance deployments, leave this setting at `false` (default) to maintain replay attack protection. For multi-replica deployments, set to `true` and consider implementing a shared cache backend (Redis/Memcached) if replay detection is required.

## Usage Examples

### Basic Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-basic
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

### With Excluded URLs (Public Access Paths)

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-open-urls
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      excludedURLs:
        - /login        # covers /login, /login/me, /login/reminder etc.
        - /public-data
        - /health
        - /metrics
```

### With Email Domain Restrictions

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-domain-restricted
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      allowedUserDomains:
        - company.com
        - subsidiary.com
```

### With Specific User Access

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-specific-users
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      allowedUsers:
        - user1@example.com
        - user2@another.org
```

### With Both Domain and Specific User Access

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-domain-and-users
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      allowedUserDomains:
        - company.com
      allowedUsers:
        - special-user@gmail.com
        - contractor@external.org
```

When configuring access control:
- If only `allowedUsers` is set, only the specified email addresses will be granted access
- If only `allowedUserDomains` is set, only users with email addresses from those domains will be granted access
- If both are set, access is granted if the user's email is in `allowedUsers` OR their email's domain is in `allowedUserDomains`
- If neither is set, any authenticated user will be granted access
- Email matching is case-insensitive

### With Role-Based Access Control

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-rbac
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      allowedRolesAndGroups:
        - admin
        - developer
```

### With Cookie Domain Configuration (Multi-Subdomain Setup)

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-multi-subdomain
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      cookieDomain: .example.com  # Allows cookies to be shared across all subdomains
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

**Important**: The `cookieDomain` parameter is crucial when running behind a reverse proxy or when your application serves multiple subdomains. Without it, cookies may be created with inconsistent domains, leading to authentication issues like "CSRF token missing in session" errors.

### With Custom Logging and Rate Limiting

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-custom-settings
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      logLevel: debug    # Options: debug, info, error (default: info)
      rateLimit: 500     # Requests per second (default: 100)
      forceHTTPS: false  # Default is true for security
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

### With Custom Post-Logout Redirect

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-custom-logout
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      postLogoutRedirectURI: /logged-out-page  # Where to redirect after logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

### With Templated Headers

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-headers
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
      headers:
        # Using double curly braces to escape template expressions
        - name: "X-User-Email"
          value: "{{{{.Claims.email}}}}"
        - name: "X-User-ID"
          value: "{{{{.Claims.sub}}}}"
        - name: "Authorization"
          value: "Bearer {{{{.AccessToken}}}}"
        - name: "X-User-Roles"
          value: "{{{{range $i, $e := .Claims.roles}}}}{{{{if $i}}}},{{{{end}}}}{{{{$e}}}}{{{{end}}}}"
        - name: "X-Is-Admin"
          value: "{{{{if eq .Claims.role \"admin\"}}}}true{{{{else}}}}false{{{{end}}}}"
```

### With PKCE Enabled

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-pkce
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: 1234567890.apps.googleusercontent.com
      clientSecret: your-client-secret
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      enablePKCE: true  # Enables PKCE for added security
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

## Provider-Specific Configuration Examples

### Google OIDC Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-google
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: your-google-client-id.apps.googleusercontent.com
      clientSecret: your-google-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
        # Note: DO NOT manually add offline_access scope for Google
        # The middleware automatically handles Google-specific requirements
      refreshGracePeriodSeconds: 300  # Optional: Start refresh 5 min before expiry
      allowedUserDomains:
        - your-gsuite-domain.com  # Optional: Restrict to workspace users
```

### Azure AD Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-azure
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://login.microsoftonline.com/your-tenant-id/v2.0
      clientID: your-azure-ad-client-id
      clientSecret: your-azure-ad-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # For group/role claims, configure in Azure AD Token Configuration
      allowedUserDomains:
        - yourcompany.com
      allowedRolesAndGroups:
        - "group-object-id-1"  # Azure AD group Object IDs
        - "AppRoleName"        # Application role names
```

### Auth0 Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth0
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-auth0-domain.auth0.com
      clientID: your-auth0-client-id
      clientSecret: your-auth0-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout

      # Audience configuration for custom APIs
      audience: "https://my-api.example.com"  # Your API identifier from Auth0
      strictAudienceValidation: true          # Enforce proper audience validation

      scopes:
        - read:custom_data  # Custom scopes as needed
      allowedRolesAndGroups:
        - "https://your-app.com/roles:admin"  # Namespaced claims from Actions
        - editor
      postLogoutRedirectURI: /logged-out-page  # Must be in Auth0 Allowed Logout URLs
```

**Note**: For detailed Auth0 audience configuration including opaque tokens and all security scenarios, see [AUTH0_AUDIENCE_GUIDE.md](docs/AUTH0_AUDIENCE_GUIDE.md).

### Okta Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-okta
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-tenant.okta.com/oauth2/default
      clientID: your-okta-client-id
      clientSecret: your-okta-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - groups  # Include groups in token claims
      allowedRolesAndGroups:
        - admin
        - developer
        - "Everyone"  # Default Okta group
```

### Keycloak Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-keycloak
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-keycloak-domain/auth/realms/your-realm
      clientID: your-keycloak-client-id
      clientSecret: your-keycloak-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles
        - groups
      allowedRolesAndGroups:
        - admin
        - editor
      # Ensure Keycloak client mappers add necessary claims to ID Token
```

### AWS Cognito Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-cognito
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_YourUserPool
      clientID: your-cognito-client-id
      clientSecret: your-cognito-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - aws.cognito.signin.user.admin  # Cognito-specific scope
      allowedRolesAndGroups:
        - admin
        - user
```

### GitLab Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-gitlab
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://gitlab.com
      clientID: your-gitlab-client-id
      clientSecret: your-gitlab-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - read_user
        - read_api
      allowedUserDomains:
        - yourcompany.com
```

### GitHub OAuth Configuration ⚠️

**Warning**: GitHub uses OAuth 2.0, not OpenID Connect. Use only for API access, not user authentication.

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oauth-github
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://github.com/login/oauth
      clientID: your-github-client-id
      clientSecret: your-github-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - user:email
        - read:user
      # Note: No ID tokens available, only access tokens for GitHub API
      # No refresh tokens - users must re-authenticate when tokens expire
```

The middleware automatically detects each provider and applies the necessary adjustments to ensure proper authentication and token refresh.

### Keeping Secrets Secret in Kubernetes

For Kubernetes environments, you can reference secrets instead of hardcoding sensitive values:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-secrets
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: urn:k8s:secret:traefik-middleware-oidc:ISSUER
      clientID: urn:k8s:secret:traefik-middleware-oidc:CLIENT_ID
      clientSecret: urn:k8s:secret:traefik-middleware-oidc:SECRET
      sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
      callbackURL: /oauth2/callback
      logoutURL: /oauth2/logout
      scopes:
        - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
```

Don't forget to create the secret:

```bash
kubectl create secret generic traefik-middleware-oidc \
  --from-literal=ISSUER=https://accounts.google.com \
  --from-literal=CLIENT_ID=1234567890.apps.googleusercontent.com \
  --from-literal=SECRET=your-client-secret \
  -n traefik
```

## Complete Docker Compose Example

Here's a complete example of using the middleware with Docker Compose:

```yaml
version: "3.7"

services:
  traefik:
    image: traefik:v3.2.1
    command:
      - "--experimental.plugins.traefikoidc.modulename=github.com/lukaszraczylo/traefikoidc"
      - "--experimental.plugins.traefikoidc.version=v0.7.10"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./traefik-config/traefik.yml:/etc/traefik/traefik.yml
      - ./traefik-config/dynamic-configuration.yml:/etc/traefik/dynamic-configuration.yml
    labels:
      - "traefik.http.routers.dash.rule=Host(`dash.localhost`)"
      - "traefik.http.routers.dash.service=api@internal"
    ports:
      - "80:80"

  hello:
    image: containous/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.hello.entrypoints=http
      - traefik.http.routers.hello.rule=Host(`hello.localhost`)
      - traefik.http.services.hello.loadbalancer.server.port=80
      - traefik.http.routers.hello.middlewares=my-plugin@file

  whoami:
    image: jwilder/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.entrypoints=http
      - traefik.http.routers.whoami.rule=Host(`whoami.localhost`)
      - traefik.http.services.whoami.loadbalancer.server.port=8000
      - traefik.http.routers.whoami.middlewares=my-plugin@file
```

`traefik-config/traefik.yml`:
```yaml
log:
  level: INFO

experimental:
  localPlugins:
    traefikoidc:
      moduleName: github.com/lukaszraczylo/traefikoidc

# API and dashboard configuration
api:
  dashboard: true
  insecure: true

entryPoints:
  http:
    address: ":80"
    forwardedHeaders:
      insecure: true

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
  file:
    filename: /etc/traefik/dynamic-configuration.yml
```

`traefik-config/dynamic-configuration.yml`:
```yaml
http:
  middlewares:
    my-plugin:
      plugin:
        traefikoidc:
          providerURL: https://accounts.google.com
          clientID: 1234567890.apps.googleusercontent.com
          clientSecret: your-client-secret
          callbackURL: /oauth2/callback
          logoutURL: /oauth2/logout
          postLogoutRedirectURI: /logged-out-page
          sessionEncryptionKey: potato-secret-is-at-least-32-bytes-long
          scopes:
            - roles  # Appended to defaults: ["openid", "profile", "email", "roles"]
          allowedUserDomains:
            - company.com
          allowedUsers:
            - special-user@gmail.com
            - contractor@external.org
          allowedRolesAndGroups:
            - admin
            - developer
          forceHTTPS: false
          logLevel: debug
          rateLimit: 100
          excludedURLs:
            - /login
            - /public
            - /health
            - /metrics
          headers:
            # Using YAML literal style to prevent Traefik from pre-evaluating templates
            - name: "X-User-Email"
              value: |
                {{.Claims.email}}
            - name: "X-User-ID"
              value: |
                {{.Claims.sub}}
            - name: "Authorization"
              value: |
                Bearer {{.AccessToken}}
            - name: "X-User-Roles"
              value: |
                {{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}
```

### Templated Headers

The middleware supports setting custom HTTP headers with values templated from OIDC claims and tokens. This allows you to pass authentication information to downstream services in a flexible, customized format.

Templates can access the following variables:
- `{{.Claims.field}}` - Access individual claims from the ID token (e.g., `{{.Claims.email}}`, `{{.Claims.sub}}`)
- `{{.AccessToken}}` - The raw access token string
- `{{.IdToken}}` - The raw ID token string (same as AccessToken in most configurations)
- `{{.RefreshToken}}` - The raw refresh token string

**⚠️ Important: Template Escaping**

If you encounter the error `can't evaluate field AccessToken in type bool` when starting Traefik, this indicates that Traefik is attempting to evaluate the template expressions before passing them to the plugin. This is a known issue when using template syntax in Traefik plugin configurations.

**Solution:** You must escape the template expressions using double curly braces:

```yaml
headers:
  - name: "Authorization"
    value: "Bearer {{{{.AccessToken}}}}"
```

This is the only reliable method that works consistently. Here's why:

- **Double curly braces (`{{{{.AccessToken}}}}`)** ✅
  - The YAML parser converts `{{{{` → `{{` and `}}}}` → `}}`
  - Result: `Bearer {{.AccessToken}}` reaches the Go template engine correctly

- **Other methods (YAML literal style, single quotes) do NOT work** ❌
  - These methods don't prevent Traefik's YAML parser from interpreting the curly braces
  - The template syntax gets processed incorrectly before reaching the plugin

**Working example configuration:**
```yaml
headers:
  - name: "X-User-Email"
    value: "{{{{.Claims.email}}}}"
  - name: "X-User-ID"
    value: "{{{{.Claims.sub}}}}"
  - name: "Authorization"
    value: "Bearer {{{{.AccessToken}}}}"
  - name: "X-User-Name"
    value: "{{{{.Claims.given_name}}}} {{{{.Claims.family_name}}}}"
```

**Advanced template examples:**

Conditional logic:
```yaml
headers:
  - name: "X-Is-Admin"
    value: "{{{{if eq .Claims.role \"admin\"}}}}true{{{{else}}}}false{{{{end}}}}"
```

Array handling:
```yaml
headers:
  - name: "X-User-Roles"
    value: "{{{{range $i, $e := .Claims.roles}}}}{{{{if $i}}}},{{{{end}}}}{{{{$e}}}}{{{{end}}}}"
```

**Notes:**
- Variable names are case-sensitive (use `.Claims`, not `.claims`)
- Missing claims will result in `<no value>` in the header value
- The middleware validates templates during startup and logs errors for invalid templates
- Always use double curly braces (`{{{{` and `}}}}`) to escape template expressions in YAML configuration files

### Default Headers Set for Downstream Services


When a user is authenticated, the middleware sets the following headers for downstream services:

- `X-Forwarded-User`: The user's email address
- `X-User-Groups`: Comma-separated list of user groups (if available)
- `X-User-Roles`: Comma-separated list of user roles (if available)
- `X-Auth-Request-Redirect`: The original request URI
- `X-Auth-Request-User`: The user's email address
- `X-Auth-Request-Token`: The user's access token

### Security Headers

The middleware also sets the following security headers:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Provider Configuration Recommendations

**Important: ID Token Validation**

This Traefik OIDC plugin performs authentication and extracts user claims (like email, roles, groups) exclusively from the **ID Token** provided by your OIDC provider. It does not primarily use the Access Token for these critical functions. Therefore, it is crucial to ensure that all necessary claims are included in the ID Token itself. A common issue is that some OIDC providers might, by default, place certain claims only in the Access Token or UserInfo endpoint.

This section provides guidance on configuring popular OIDC providers to work optimally with this plugin.

### Google Workspace / Google Cloud Identity

Google's OIDC implementation is well-supported with automatic configuration.

*   **Automatic Configuration**: The middleware automatically detects Google and applies required settings:
    *   Uses `access_type=offline` and `prompt=consent` for refresh tokens
    *   Filters out unsupported `offline_access` scope
    *   Handles Google-specific token refresh
*   **Setup Requirements**:
    *   Create OAuth 2.0 credentials in Google Cloud Console
    *   Configure OAuth consent screen (must be "Published" for production)
    *   Add authorized redirect URIs
*   **ID Token Claims**: Google includes standard claims like `email`, `sub`, `name`, `given_name`, `family_name`, `picture`
*   **Hosted Domain**: For Google Workspace, the `hd` claim contains the organization domain
*   **Best Practices**: Use `providerURL: https://accounts.google.com`

### Azure AD (Microsoft Entra ID)

Azure AD provides comprehensive enterprise OIDC support.

*   **Tenant Configuration**: Use tenant-specific endpoint: `https://login.microsoftonline.com/{tenant-id}/v2.0`
*   **Group Claims**: Configure in App Registration → Token Configuration → Add groups claim
*   **ID Token Claims**: Includes `email`, `name`, `preferred_username`, `oid` by default
*   **Group Handling**: Be aware of group "overage" - too many groups results in a groups claim link instead of embedded groups
*   **Optional Claims**: Add custom claims via Token Configuration section
*   **Multi-tenant**: Supports both single-tenant and multi-tenant applications

### Auth0

Auth0 provides flexible OIDC with custom claims support.

*   **Custom Claims**: Use Auth0 Actions (recommended) or Rules to add claims to ID Token:
    ```javascript
    // Auth0 Action example
    exports.onExecutePostLogin = async (event, api) => {
      const namespace = 'https://your-app.com/';
      if (event.authorization) {
        api.idToken.setCustomClaim(namespace + 'roles', event.authorization.roles);
        api.idToken.setCustomClaim('email', event.user.email);
      }
    };
    ```
*   **Logout Configuration**: Ensure `postLogoutRedirectURI` is in "Allowed Logout URLs"
*   **Application Type**: Set to "Regular Web Application" for server-side flows
*   **Refresh Tokens**: Automatically handled with `offline_access` scope

### Okta

Okta provides enterprise-grade OIDC with extensive customization.

*   **Application Setup**: Create OIDC Web Application in Okta Admin Console
*   **Authorization Server**: Use default (`/oauth2/default`) or custom authorization server
*   **Group Claims**: Configure Groups claim in authorization server to include user groups
*   **Scopes**: Default scopes sufficient; add `groups` scope for group information
*   **Sign-On Policy**: Configure authentication policies and MFA requirements
*   **Custom Claims**: Add custom attributes via user profiles and authorization server claims

### Keycloak

Keycloak is highly configurable, requiring proper client mapper setup.

*   **Client Mappers**: Essential for including claims in ID Token:
    *   **Email**: User Property mapper for `email` with "Add to ID token" enabled
    *   **Roles**: User Client Role or User Realm Role mappers with "Add to ID token" enabled
    *   **Groups**: Group Membership mapper with "Add to ID token" enabled
*   **Token Claim Names**: Use mapper "Token Claim Name" in `allowedRolesAndGroups` configuration
*   **Realm Configuration**: Ensure proper realm settings and client configuration
*   **Issuer URL Format**: `https://your-keycloak/auth/realms/your-realm`
*   **Troubleshooting**: Verify mappers in Clients → Your Client → Mappers tab

### AWS Cognito

AWS Cognito provides managed OIDC with regional deployment.

*   **User Pool Setup**: Create User Pool with proper app client configuration
*   **App Client**: Enable "Authorization code grant" and configure callback URLs
*   **Regional Endpoints**: Auto-detected from issuer URL format
*   **Custom Attributes**: Configure custom attributes and map to claims
*   **Groups**: Use Cognito Groups for role-based access control
*   **Federation**: Supports federated identity providers (SAML, social providers)

### GitLab

GitLab supports OIDC for both GitLab.com and self-hosted instances.

*   **Application Registration**: Create in GitLab Admin Area → Applications
*   **Scopes**: Use `openid`, `profile`, `email` for basic claims
*   **Self-hosted**: Use your GitLab instance URL as `providerURL`
*   **GitLab.com**: Use `https://gitlab.com` as `providerURL`
*   **Group Claims**: May require custom configuration for group information
*   **API Access**: Include `read_api` scope for GitLab API access via access token

### GitHub (OAuth 2.0 Only) ⚠️

**Important**: GitHub uses OAuth 2.0, not OpenID Connect.

*   **OAuth App Setup**: Register OAuth App in GitHub Settings → Developer settings
*   **Limitations**:
    *   No ID tokens (access tokens only)
    *   No refresh tokens (tokens expire, requiring re-authentication)
    *   No standard OIDC claims
*   **Use Cases**: API access only, not suitable for user authentication with claims
*   **Scopes**: Use `user:email`, `read:user` for basic profile access
*   **Detection**: Auto-detected from `github.com` in issuer URL

### Auth0

Auth0 is generally OIDC compliant and works well.

*   **ID Token Claims**:
    *   To add custom claims or standard claims not included by default (like roles or permissions) to the ID Token, you'll need to use Auth0 Rules or Actions.
    *   **Using Actions (Recommended)**: Create a custom Action that runs after login to add claims to the ID Token. Example:
        ```javascript
        // Auth0 Action to add email and roles to ID Token
        exports.onExecutePostLogin = async (event, api) => {
          const namespace = 'https://your-app.com/'; // Or your custom namespace
          if (event.authorization) {
            api.idToken.setCustomClaim(namespace + 'roles', event.authorization.roles);
            api.idToken.setCustomClaim('email', event.user.email); // Standard claim, ensure it's there
            // Add other claims as needed
          }
        };
        ```
    *   Ensure the claims you add (e.g., `https://your-app.com/roles`) are then used in the plugin's `allowedRolesAndGroups` or `headers` configuration.
*   **Scopes**: Request appropriate scopes. You might need custom scopes if your Actions/Rules depend on them to add specific claims.
*   **Endpoints**: Your `providerURL` will be `https://your-auth0-domain.auth0.com`.
*   **Logout**: Ensure `postLogoutRedirectURI` is registered in your Auth0 application settings under "Allowed Logout URLs".

### Generic OIDC Providers

For other OIDC providers (e.g., Okta, Zitadel, self-hosted solutions):

*   **ID Token is Key**: The primary requirement is that all claims needed for authentication decisions (email, roles, groups, custom attributes for headers) **must** be included in the ID Token.
*   **Check Provider Documentation**: Consult your OIDC provider's documentation on how to:
    *   Configure client applications.
    *   Map user attributes, roles, or group memberships to claims in the ID Token.
    *   Define custom scopes if they are necessary to include certain claims.
*   **Standard Endpoints**: Ensure your provider exposes a standard OIDC discovery document (`.well-known/openid-configuration`) at the `providerURL`. The plugin uses this to find authorization, token, JWKS, and end_session endpoints.
*   **Scopes**: Always include `openid` in your scopes. `profile` and `email` are generally recommended. Add other scopes as required by your provider to release specific claims to the ID Token.
*   **Troubleshooting**: If the plugin isn't working as expected (e.g., access denied, claims missing), the first step is to decode the ID Token received from your provider (e.g., using jwt.io) to verify its contents. This will show you exactly what claims the plugin is seeing.

For common issues and general troubleshooting, please refer to the [Troubleshooting](#troubleshooting) section.

## Troubleshooting

### Logging

Set the `logLevel` to `debug` to get more detailed logs:

```yaml
logLevel: debug
```

### Common Issues

1. **Token verification failed**: Check that your `providerURL` is correct and accessible.
2. **Session encryption key too short**: Ensure your `sessionEncryptionKey` is at least 32 bytes long.
3. **No matching public key found**: The JWKS endpoint might be unavailable or the token's key ID (kid) doesn't match any key in the JWKS.
4. **Access denied: Your email domain is not allowed**: The user's email domain is not in the `allowedUserDomains` list.
5. **Access denied: You do not have any of the allowed roles or groups**: The user doesn't have any of the roles or groups specified in `allowedRolesAndGroups`.
6. **"can't evaluate field AccessToken in type bool" error**: This error occurs when Traefik attempts to evaluate template expressions in the headers configuration before passing them to the plugin. To fix this:
   - Use double curly braces to escape template expressions: `value: "Bearer {{{{.AccessToken}}}}"`
   - This is the only reliable method that works with Traefik's YAML parsing
   - See the [Templated Headers](#templated-headers) section for complete examples

#### Provider-Specific Issues

7. **Google sessions expire after ~1 hour**: If using Google as the OIDC provider and sessions expire prematurely:
   - Do NOT manually add the `offline_access` scope. Google rejects this scope as invalid.
   - The middleware automatically applies Google parameters (`access_type=offline` and `prompt=consent`).
   - Ensure your Google Cloud OAuth consent screen is "Published" for production.
   - "Testing" mode limits refresh token validity.

8. **Keycloak: Claims Missing from ID Token**:
   - Configure client mappers to add email, roles, groups to ID Token
   - Check "Add to ID token" is enabled for all required mappers
   - Verify "Token Claim Name" matches your configuration

9. **Azure AD: Group overage issues**:
   - Users with many groups may receive a groups link instead of embedded groups
   - Consider using app roles instead of groups for many-group scenarios
   - Configure group claims in App Registration → Token Configuration

10. **Auth0: Custom claims not appearing**:
    - Use Auth0 Actions (not Rules) to add custom claims to ID Token
    - Ensure namespaced claims follow format: `https://your-app.com/claim`
    - Add claims to ID token specifically, not just access token

11. **Okta: Authorization server issues**:
    - Verify using correct authorization server endpoint (`/oauth2/default` or custom)
    - Ensure Groups claim is configured in authorization server
    - Check application assignment and user group membership

12. **AWS Cognito: Regional endpoint errors**:
    - Use correct regional endpoint format: `cognito-idp.{region}.amazonaws.com`
    - Verify User Pool ID is correct in issuer URL
    - Check app client has authorization code grant enabled

13. **GitLab: Self-hosted instance issues**:
    - Ensure issuer URL points to your GitLab instance root
    - Verify application is created in Admin Area → Applications
    - Check redirect URI configuration matches exactly

14. **GitHub: Limited functionality warnings**:
    - Remember GitHub is OAuth 2.0 only, not OIDC
    - No ID tokens available (access tokens only)
    - No refresh tokens (re-authentication required on expiry)
    - Use only for GitHub API access, not user authentication

### Provider Warnings and Recommendations

The middleware includes built-in warnings for provider-specific limitations. Check your logs for important notices about:

- **GitHub OAuth 2.0 limitations** (no OIDC support)
- **Auth0 offline_access scope requirements**
- **Keycloak URL pattern requirements**
- **AWS Cognito regional endpoint requirements**
- **Provider-specific setup recommendations**

For detailed provider-specific guidance, see the [Provider-Specific Configuration Examples](#provider-specific-configuration-examples) section.

## Recent Improvements

### Security Features (v0.4.0+)

- **Security Headers**: Complete security headers system with CSP, HSTS, CORS, and XSS protection
- **Multiple Security Profiles**: Choose from default, strict, development, API, or custom security configurations
- **Enhanced Token Validation**: Improved JWT validation with comprehensive security checks
- **Advanced Rate Limiting**: Configurable rate limiting to prevent abuse

### User Experience (v0.4.0+)

- **Automatic Provider Detection**: Seamless configuration for major OIDC providers
- **Improved Error Handling**: Better error messages and graceful degradation
- **Enhanced Session Management**: More reliable session handling with automatic cleanup
- **Flexible Configuration**: Expanded configuration options for different deployment scenarios

### Reliability (v0.4.0+)

- **Automatic Token Refresh**: Proactive token refresh to prevent authentication interruptions
- **Memory Management**: Improved memory efficiency and automatic resource cleanup
- **Better Provider Support**: Enhanced compatibility with provider-specific features
- **Comprehensive Testing**: Extensive test coverage ensures reliability in production

## Architecture Overview

### Design Principles

The middleware is designed with the following principles:

- **Reliability**: Automatic error recovery and graceful degradation
- **Security**: Comprehensive security measures and validation
- **Performance**: Efficient resource usage and caching
- **Flexibility**: Extensive configuration options for different use cases
- **Compatibility**: Support for all major OIDC providers with automatic detection

### Key Features

- **Automatic Session Management**: Handles session lifecycle, cleanup, and security
- **Provider Integration**: Seamless integration with OIDC providers including auto-discovery
- **Security Integration**: Built-in security headers and protection mechanisms
- **Resource Management**: Efficient memory usage and automatic cleanup
- **Error Handling**: Comprehensive error recovery and user-friendly error messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines

1. **Memory Management**: Ensure all goroutines can be cancelled and resources are bounded
2. **Testing**: Add tests for new features, including memory leak tests where appropriate
3. **Race Conditions**: Run tests with `-race` flag to detect race conditions
4. **Documentation**: Update README and .traefik.yml for any new configuration options
