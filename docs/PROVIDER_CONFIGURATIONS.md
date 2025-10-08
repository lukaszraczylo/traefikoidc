# Provider-Specific Configuration Guide

This guide covers the configuration requirements and best practices for each supported OIDC provider.

## Table of Contents

- [Google](#google)
- [Microsoft Azure AD](#microsoft-azure-ad)
- [Auth0](#auth0)
- [GitHub](#github)
- [GitLab](#gitlab)
- [AWS Cognito](#aws-cognito)
- [Keycloak](#keycloak)
- [Okta](#okta)
- [Generic OIDC](#generic-oidc)

---

## Google

### Provider URL
```yaml
providerUrl: "https://accounts.google.com"
```

### Required Configuration
```yaml
clientId: "your-google-client-id.apps.googleusercontent.com"
clientSecret: "your-google-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email"]
```

### Google-Specific Features
- **Automatic offline access**: Google provider automatically adds `access_type=offline` and `prompt=consent`
- **Scope filtering**: Automatically removes `offline_access` scope (not used by Google)
- **Refresh token support**: Fully supported
- **Domain restrictions**: Can restrict by Google Workspace domains

### Example Configuration
```yaml
# Traefik dynamic configuration
http:
  middlewares:
    google-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://accounts.google.com"
          clientId: "123456789-abcdef.apps.googleusercontent.com"
          clientSecret: "GOCSPX-your-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email"]
          allowedUserDomains: ["example.com", "company.org"]
          forceHttps: true
          enablePkce: true
```

### Google OAuth Console Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs: `https://your-domain.com/auth/callback`

---

## Microsoft Azure AD

### Provider URL
```yaml
# For Azure AD (single tenant)
providerUrl: "https://login.microsoftonline.com/{tenant-id}/v2.0"

# For Azure AD (multi-tenant)
providerUrl: "https://login.microsoftonline.com/common/v2.0"
```

### Required Configuration
```yaml
clientId: "your-azure-application-id"
clientSecret: "your-azure-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email", "offline_access"]
```

### Azure-Specific Features
- **Response mode**: Automatically adds `response_mode=query`
- **Offline access**: Requires `offline_access` scope for refresh tokens
- **Access token validation**: Supports both JWT and opaque access tokens
- **Tenant isolation**: Can restrict to specific Azure AD tenants
- **Application ID URI**: Supports custom audience for protected APIs

### Example Configuration (Basic)
```yaml
http:
  middlewares:
    azure-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://login.microsoftonline.com/common/v2.0"
          clientId: "12345678-1234-1234-1234-123456789abc"
          clientSecret: "your-azure-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          postLogoutRedirectUri: "https://app.example.com"
          scopes: ["openid", "profile", "email", "offline_access"]
          allowedRolesAndGroups: ["App.Users", "Admin.Group"]
          forceHttps: true
```

### Azure AD API Configuration (Application ID URI)

When exposing your application as an API with a custom Application ID URI, you need to specify the `audience` parameter. Azure AD includes the Application ID URI in the JWT `aud` claim.

```yaml
http:
  middlewares:
    azure-api-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://login.microsoftonline.com/common/v2.0"
          clientId: "12345678-1234-1234-1234-123456789abc"
          clientSecret: "your-azure-client-secret"
          # Specify the Application ID URI as audience
          audience: "api://12345678-1234-1234-1234-123456789abc"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email", "offline_access"]
          forceHttps: true
```

**Important**:
- The `audience` parameter should match your Application ID URI (typically `api://{app-id}`)
- Find your Application ID URI in Azure Portal → App Registration → Expose an API → Application ID URI
- Without the `audience` parameter, access tokens with custom audiences will be rejected
- For ID token validation only (no API access), you can omit the `audience` parameter

### Azure App Registration Setup
1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Create new registration
4. Add redirect URI: `https://your-domain.com/auth/callback`
5. Create client secret in "Certificates & secrets"
6. Configure API permissions for required scopes

### Azure AD API Exposure Setup (for custom audiences)
1. In your App Registration, go to "Expose an API"
2. Set the Application ID URI (e.g., `api://12345678-1234-1234-1234-123456789abc`)
3. Add any custom scopes your API exposes
4. Update the middleware configuration to include the `audience` parameter with this URI

---

## Auth0

### Provider URL
```yaml
providerUrl: "https://your-domain.auth0.com"
```

### Required Configuration
```yaml
clientId: "your-auth0-client-id"
clientSecret: "your-auth0-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email", "offline_access"]
```

### Auth0-Specific Features
- **Custom domains**: Supports Auth0 custom domains
- **Rules and hooks**: Leverages Auth0's extensibility
- **Social connections**: Works with Auth0's social identity providers
- **Offline access**: Requires `offline_access` scope
- **API audiences**: Supports custom audience for API access tokens

### Example Configuration (Basic)
```yaml
http:
  middlewares:
    auth0-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://company.auth0.com"
          clientId: "abcdef123456789"
          clientSecret: "your-auth0-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          postLogoutRedirectUri: "https://app.example.com"
          scopes: ["openid", "profile", "email", "offline_access"]
          allowedUsers: ["user@example.com", "admin@company.com"]
          forceHttps: true
          enablePkce: true
```

### Auth0 API Configuration (Custom Audience)

When using Auth0 APIs with custom audience parameters, you need to specify the `audience` field. Auth0 includes the API identifier in the JWT `aud` claim instead of the `clientId`.

```yaml
http:
  middlewares:
    auth0-api-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://company.auth0.com"
          clientId: "abcdef123456789"
          clientSecret: "your-auth0-client-secret"
          # Specify the Auth0 API identifier as audience
          audience: "https://api.company.com"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email", "offline_access"]
          forceHttps: true
          enablePkce: true
```

**Important**:
- The `audience` parameter should match your Auth0 API identifier (not the client ID)
- Find your API identifier in Auth0 Dashboard → APIs → Your API → Settings → Identifier
- Without the `audience` parameter, access tokens with custom audiences will be rejected with "invalid audience" error
- For ID token validation only (no APIs), you can omit the `audience` parameter

### Auth0 Application Setup
1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Create new application (Regular Web Application)
3. Configure allowed callback URLs: `https://your-domain.com/auth/callback`
4. Configure allowed logout URLs: `https://your-domain.com/auth/logout`
5. Enable OIDC Conformant in Advanced Settings

### Auth0 API Setup (for custom audiences)
1. Go to Auth0 Dashboard → APIs
2. Create a new API or select existing API
3. Note the "Identifier" field (e.g., `https://api.company.com`) - this is your `audience` value
4. In API Settings → Machine to Machine Applications, authorize your application
5. Configure API permissions/scopes as needed
6. Use the API identifier as the `audience` parameter in your configuration

---

## GitHub

### Provider URL
```yaml
providerUrl: "https://github.com"
```

### Required Configuration
```yaml
clientId: "your-github-client-id"
clientSecret: "your-github-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["read:user", "user:email"]
```

### GitHub-Specific Features
- **Organization membership**: Can restrict by GitHub organization
- **Team membership**: Can restrict by specific teams
- **Limited OIDC**: GitHub has limited OIDC support
- **Email verification**: Requires verified email addresses

### Example Configuration
```yaml
http:
  middlewares:
    github-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://github.com"
          clientId: "Iv1.abcdef123456"
          clientSecret: "your-github-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["read:user", "user:email"]
          allowedUsers: ["octocat", "github-user"]
          forceHttps: true
```

### GitHub OAuth App Setup
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create new OAuth App
3. Set Authorization callback URL: `https://your-domain.com/auth/callback`
4. Note the Client ID and generate Client Secret

---

## GitLab

### Provider URL
```yaml
# GitLab.com
providerUrl: "https://gitlab.com"

# Self-hosted GitLab
providerUrl: "https://gitlab.your-company.com"
```

### Required Configuration
```yaml
clientId: "your-gitlab-application-id"
clientSecret: "your-gitlab-application-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email"]
```

### GitLab-Specific Features
- **Self-hosted support**: Works with self-hosted GitLab instances
- **Group membership**: Can restrict by GitLab groups
- **Project access**: Can validate project permissions
- **Offline access**: Supports refresh tokens without requiring `offline_access` scope

### Example Configuration
```yaml
http:
  middlewares:
    gitlab-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://gitlab.com"
          clientId: "abcdef123456789"
          clientSecret: "your-gitlab-application-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email"]
          # Note: GitLab doesn't support the offline_access scope.
          # Refresh tokens are issued automatically for the openid scope.
          allowedRolesAndGroups: ["developers", "maintainers"]
          forceHttps: true
          enablePkce: true
```

### GitLab Application Setup
1. Go to GitLab Settings > Applications
2. Create new application
3. Add scopes: `openid`, `profile`, `email`
4. Set redirect URI: `https://your-domain.com/auth/callback`
5. Save and note the Application ID and Secret

---

## AWS Cognito

### Provider URL
```yaml
providerUrl: "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}"
```

### Required Configuration
```yaml
clientId: "your-cognito-app-client-id"
clientSecret: "your-cognito-app-client-secret"  # If app client has secret
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email"]
```

### Cognito-Specific Features
- **User pools**: Integrates with Cognito User Pools
- **Custom attributes**: Supports custom user attributes
- **Groups**: Can validate Cognito user group membership
- **Regional endpoints**: Requires region-specific URLs

### Example Configuration
```yaml
http:
  middlewares:
    cognito-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABCDEF123"
          clientId: "1234567890abcdefghij"
          clientSecret: "your-cognito-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email"]
          allowedRolesAndGroups: ["admin", "users"]
          forceHttps: true
```

### AWS Cognito Setup
1. Create Cognito User Pool
2. Create App Client with OIDC scopes
3. Configure App Client settings:
   - Callback URLs: `https://your-domain.com/auth/callback`
   - Sign out URLs: `https://your-domain.com/auth/logout`
   - OAuth flows: Authorization code grant
4. Configure hosted UI domain (optional)

---

## Keycloak

### Provider URL
```yaml
providerUrl: "https://keycloak.your-company.com/realms/{realm-name}"
```

### Required Configuration
```yaml
clientId: "your-keycloak-client-id"
clientSecret: "your-keycloak-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email"]
```

### Keycloak-Specific Features
- **Realm support**: Multi-realm deployments
- **Custom mappers**: Rich claim mapping capabilities
- **Role-based access**: Fine-grained role management
- **Offline access**: Full refresh token support

### Example Configuration
```yaml
http:
  middlewares:
    keycloak-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://keycloak.company.com/realms/employees"
          clientId: "traefik-app"
          clientSecret: "your-keycloak-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          postLogoutRedirectUri: "https://app.example.com"
          scopes: ["openid", "profile", "email", "offline_access"]
          allowedRolesAndGroups: ["app-users", "administrators"]
          forceHttps: true
          enablePkce: true
```

### Keycloak Client Setup
1. Access Keycloak Admin Console
2. Select appropriate realm
3. Create new client:
   - Client Protocol: openid-connect
   - Access Type: confidential
   - Valid Redirect URIs: `https://your-domain.com/auth/callback`
4. Configure client scopes and mappers
5. Generate client secret in Credentials tab

---

## Okta

### Provider URL
```yaml
providerUrl: "https://your-domain.okta.com"
```

### Required Configuration
```yaml
clientId: "your-okta-client-id"
clientSecret: "your-okta-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email", "offline_access"]
```

### Okta-Specific Features
- **Custom authorization servers**: Supports custom auth servers
- **Group claims**: Rich group membership information
- **Universal Directory**: Integrates with Okta's user store
- **Offline access**: Requires `offline_access` scope

### Example Configuration
```yaml
http:
  middlewares:
    okta-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://company.okta.com"
          clientId: "0oa123456789abcdef"
          clientSecret: "your-okta-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          postLogoutRedirectUri: "https://app.example.com"
          scopes: ["openid", "profile", "email", "offline_access"]
          allowedRolesAndGroups: ["Everyone", "Administrators"]
          forceHttps: true
          enablePkce: true
```

### Okta Application Setup
1. Access Okta Admin Console
2. Go to Applications > Create App Integration
3. Select OIDC - OpenID Connect
4. Choose Web Application
5. Configure:
   - Sign-in redirect URIs: `https://your-domain.com/auth/callback`
   - Sign-out redirect URIs: `https://your-domain.com/auth/logout`
   - Grant types: Authorization Code, Refresh Token
6. Assign users or groups

---

## Generic OIDC

### Provider URL
```yaml
providerUrl: "https://your-oidc-provider.com"
```

### Required Configuration
```yaml
clientId: "your-client-id"
clientSecret: "your-client-secret"
callbackUrl: "https://your-domain.com/auth/callback"
scopes: ["openid", "profile", "email"]
```

### Generic Features
- **Standards compliance**: Works with any OIDC-compliant provider
- **Auto-discovery**: Uses `.well-known/openid-configuration` endpoint
- **Flexible scopes**: Supports custom scope requirements
- **Custom claims**: Works with provider-specific claims

### Example Configuration
```yaml
http:
  middlewares:
    generic-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://oidc.your-provider.com"
          clientId: "your-client-id"
          clientSecret: "your-client-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          logoutUrl: "https://app.example.com/auth/logout"
          scopes: ["openid", "profile", "email"]
          forceHttps: true
          enablePkce: true
```

---

## Automatic Scope Filtering

### Overview

The middleware automatically filters OAuth scopes based on the provider's capabilities declared in their OIDC discovery document (`.well-known/openid-configuration`). This prevents authentication failures when providers reject unsupported scopes.

### How It Works

1. **Discovery Document Parsing**: The middleware fetches the provider's discovery document and extracts the `scopes_supported` field
2. **Intelligent Filtering**: Requested scopes are filtered to only include those the provider supports
3. **Fallback Behavior**: If the provider doesn't declare `scopes_supported`, all requested scopes are used (backward compatible)
4. **Provider-Specific Handling**: Special logic for Google and Azure is preserved and applied after filtering

### Example Scenarios

#### Self-Hosted GitLab

**Problem**: Self-hosted GitLab instances reject the `offline_access` scope with error:
```
The requested scope is invalid, unknown, or malformed.
```

**Solution**: The middleware automatically detects this by:
1. Reading GitLab's discovery document at `https://gitlab.example.com/.well-known/openid-configuration`
2. Observing that `offline_access` is NOT in the `scopes_supported` list
3. Filtering out `offline_access` from the request
4. Authentication succeeds

**Configuration**:
```yaml
http:
  middlewares:
    gitlab-oidc:
      plugin:
        traefik-oidc:
          providerUrl: "https://gitlab.example.com"
          clientId: "your-gitlab-application-id"
          clientSecret: "your-gitlab-application-secret"
          callbackUrl: "https://app.example.com/auth/callback"
          scopes: ["openid", "profile", "email", "offline_access"]
          # Even though offline_access is listed, it will be automatically
          # filtered out if GitLab doesn't support it
```

#### Auth0 or Keycloak

These providers typically support `offline_access` and it will be included:

```yaml
# Auth0 scopes_supported: ["openid", "profile", "email", "offline_access", ...]
# Result: All requested scopes are sent
```

### Benefits

1. **Self-Hosted Support**: Works seamlessly with self-hosted provider instances
2. **No Manual Configuration**: No need to know which scopes each provider supports
3. **Error Prevention**: Eliminates "invalid scope" authentication failures
4. **Standards Compliant**: Uses official OIDC discovery specification (RFC 8414)
5. **Backward Compatible**: Existing configurations continue to work

### Logging

The middleware provides detailed logging for scope filtering:

```
INFO: ScopeFilter: Filtered unsupported scopes for https://gitlab.example.com: [offline_access]
DEBUG: ScopeFilter: Provider https://gitlab.example.com supported scopes: [openid profile email read_user read_api]
DEBUG: ScopeFilter: Final filtered scopes: [openid profile email]
```

### Troubleshooting

**Issue**: Provider rejects scope even after filtering

**Possible Causes**:
1. Provider's discovery document is outdated
2. Provider doesn't properly implement `scopes_supported`
3. Custom authorization server with non-standard behavior

**Solutions**:
1. Use `overrideScopes: true` and explicitly list only supported scopes
2. Check the provider's discovery document manually: `curl https://your-provider/.well-known/openid-configuration`
3. Review middleware debug logs for filtering decisions

---

## Common Configuration Options

### Audience Configuration

The `audience` parameter specifies the expected JWT audience claim value. This is particularly important when using Auth0 APIs, Azure AD Application ID URIs, or other providers with custom audience requirements.

```yaml
# Optional: Custom audience for JWT validation
# If not set, defaults to clientID for backward compatibility
audience: "https://api.example.com"  # Auth0 API identifier
# OR
audience: "api://12345-guid"  # Azure AD Application ID URI
```

**When to use**:
- **Auth0**: When using Auth0 APIs with custom audience parameters
- **Azure AD**: When exposing your app as an API with Application ID URI
- **Keycloak**: When using audience-restricted tokens
- **Okta**: When using custom authorization servers with API audiences

**When to omit**:
- For standard ID token validation (default behavior)
- When the provider sets `aud` claim to your `clientID`
- For backward compatibility with existing configurations

**Security Note**: The `audience` parameter prevents token confusion attacks by ensuring tokens issued for one service cannot be used at another service.

### Security Settings
```yaml
# Force HTTPS (recommended for production)
forceHttps: true

# Enable PKCE (recommended for security)
enablePkce: true

# Session encryption key (32+ characters)
sessionEncryptionKey: "your-very-long-encryption-key-here"
```

### Access Control
```yaml
# Restrict by email addresses
allowedUsers: ["user1@example.com", "user2@example.com"]

# Restrict by email domains
allowedUserDomains: ["company.com", "partner.org"]

# Restrict by roles/groups (provider-specific)
allowedRolesAndGroups: ["admin", "users", "developers"]
```

### URLs and Endpoints
```yaml
# OAuth callback URL (must match provider config)
callbackUrl: "https://your-domain.com/auth/callback"

# Logout endpoint
logoutUrl: "https://your-domain.com/auth/logout"

# Post-logout redirect (optional)
postLogoutRedirectUri: "https://your-domain.com"

# URLs to exclude from authentication
excludedUrls: ["/health", "/metrics", "/public"]
```

### Advanced Settings
```yaml
# Override default scopes
overrideScopes: true
scopes: ["openid", "custom_scope"]

# Rate limiting (requests per second)
rateLimit: 10

# Token refresh grace period (seconds)
refreshGracePeriodSeconds: 60

# Cookie domain (for subdomain sharing)
cookieDomain: ".example.com"

# Custom headers to inject
headers:
  - name: "X-User-Email"
    value: "{{.Claims.email}}"
  - name: "X-User-Name"
    value: "{{.Claims.name}}"
```

---

## Troubleshooting

### Common Issues

1. **Invalid redirect URI**
   - Ensure callback URL exactly matches provider configuration
   - Check for HTTP vs HTTPS mismatches

2. **Scope errors**
   - Verify required scopes are configured in provider
   - Some providers require specific scopes for refresh tokens

3. **Token validation failures**
   - Check provider URL format and accessibility
   - Verify `.well-known/openid-configuration` endpoint is reachable

4. **Session issues**
   - Ensure session encryption key is properly configured
   - Check cookie domain settings for subdomain scenarios

### Debug Mode
Enable debug logging to troubleshoot configuration issues:
```yaml
logLevel: "debug"
```

This will provide detailed logs of the authentication flow and help identify configuration problems.

---

## Security Headers Configuration

The plugin includes comprehensive security headers support to protect your applications against common web vulnerabilities.

### Default Security Headers

By default, the plugin applies these security headers:

- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-XSS-Protection: 1; mode=block` - Enables XSS protection
- `Referrer-Policy: strict-origin-when-cross-origin` - Controls referrer information
- `Strict-Transport-Security` - Forces HTTPS (when HTTPS is detected)

### Security Profiles

Choose from predefined security profiles or create custom configurations:

#### Default Profile (Recommended)
```yaml
securityHeaders:
  enabled: true
  profile: "default"
```

#### Strict Profile (Maximum Security)
```yaml
securityHeaders:
  enabled: true
  profile: "strict"
  # Additional strict CSP and cross-origin policies
```

#### Development Profile (Local Development)
```yaml
securityHeaders:
  enabled: true
  profile: "development"
  # Relaxed policies for local development
```

#### API Profile (API Endpoints)
```yaml
securityHeaders:
  enabled: true
  profile: "api"
  corsEnabled: true
  corsAllowedOrigins: ["https://your-frontend.com"]
```

### Custom Security Configuration

For complete control, use the custom profile:

```yaml
securityHeaders:
  enabled: true
  profile: "custom"
  
  # Content Security Policy
  contentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
  
  # HSTS Configuration
  strictTransportSecurity: true
  strictTransportSecurityMaxAge: 31536000  # 1 year
  strictTransportSecuritySubdomains: true
  strictTransportSecurityPreload: true
  
  # Frame and content protection
  frameOptions: "DENY"  # or "SAMEORIGIN", "ALLOW-FROM uri"
  contentTypeOptions: "nosniff"
  xssProtection: "1; mode=block"
  referrerPolicy: "strict-origin-when-cross-origin"
  
  # Permissions policy (feature policy)
  permissionsPolicy: "geolocation=(), microphone=(), camera=()"
  
  # Cross-origin policies
  crossOriginEmbedderPolicy: "require-corp"
  crossOriginOpenerPolicy: "same-origin"
  crossOriginResourcePolicy: "same-origin"
  
  # CORS configuration
  corsEnabled: true
  corsAllowedOrigins: 
    - "https://app.example.com"
    - "https://*.api.example.com"
  corsAllowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  corsAllowedHeaders: ["Authorization", "Content-Type", "X-Requested-With"]
  corsAllowCredentials: true
  corsMaxAge: 86400  # 24 hours
  
  # Custom headers
  customHeaders:
    X-Custom-Header: "custom-value"
    X-API-Version: "v1"
  
  # Server identification
  disableServerHeader: true
  disablePoweredByHeader: true
```

### Complete Example with Security Headers

Here's a complete configuration example for Google OIDC with custom security headers:

```yaml
# Traefik dynamic configuration
http:
  middlewares:
    secure-google-oidc:
      plugin:
        traefik-oidc:
          # OIDC Configuration
          providerUrl: "https://accounts.google.com"
          clientId: "123456789-abcdef.apps.googleusercontent.com"
          clientSecret: "GOCSPX-your-client-secret"
          callbackUrl: "https://your-domain.com/auth/callback"
          sessionEncryptionKey: "your-32-character-encryption-key-here"
          
          # Domain restrictions
          allowedUserDomains: ["your-company.com"]
          
          # Security Headers
          securityHeaders:
            enabled: true
            profile: "strict"
            corsEnabled: true
            corsAllowedOrigins: 
              - "https://your-frontend.com"
              - "https://*.your-domain.com"
            corsAllowCredentials: true
            customHeaders:
              X-Company: "YourCompany"
              X-Environment: "production"

  routers:
    secure-app:
      rule: "Host(`your-domain.com`)"
      middlewares:
        - secure-google-oidc
      service: your-app-service
      tls:
        certResolver: letsencrypt
```

### CORS Configuration Details

For applications with frontend-backend separation, configure CORS properly:

#### Simple CORS (Single Origin)
```yaml
securityHeaders:
  corsEnabled: true
  corsAllowedOrigins: ["https://app.example.com"]
  corsAllowCredentials: true
```

#### Wildcard Subdomains
```yaml
securityHeaders:
  corsEnabled: true
  corsAllowedOrigins: ["https://*.example.com"]
  corsAllowCredentials: true
```

#### Development with Multiple Ports
```yaml
securityHeaders:
  profile: "development"
  corsEnabled: true
  corsAllowedOrigins: 
    - "http://localhost:*"
    - "http://127.0.0.1:*"
```

### Security Best Practices

1. **Always use HTTPS in production**
   - Set `forceHttps: true`
   - Configure proper TLS certificates

2. **Implement proper CSP**
   - Start with strict policy
   - Add exceptions only when necessary
   - Test thoroughly

3. **Configure CORS restrictively**
   - Only allow necessary origins
   - Use specific domains instead of wildcards when possible

4. **Enable HSTS**
   - Use long max-age values (1 year minimum)
   - Include subdomains when appropriate

5. **Monitor security headers**
   - Use browser developer tools to verify headers
   - Test with security scanning tools
   - Regularly review and update policies

### Testing Security Headers

Use browser developer tools or online tools to verify your security headers:

1. **Browser DevTools**: Check Network tab → Response Headers
2. **Online scanners**: Use securityheaders.com or observatory.mozilla.org
3. **Command line**: Use `curl -I https://your-domain.com`

Example verification:
```bash
curl -I https://your-domain.com
# Should show security headers in response
```