# Traefik OIDC Middleware

This middleware replaces the need for forward-auth and oauth2-proxy when using Traefik as a reverse proxy to support OpenID Connect (OIDC) authentication.

## Overview

The Traefik OIDC middleware provides a complete OIDC authentication solution with features like:
- Token validation and verification
- Session management
- Domain restrictions
- Role-based access control
- Token caching and blacklisting
- Rate limiting
- Excluded paths (public URLs)

The middleware has been tested with Auth0, Logto, Google and other standard OIDC providers. It includes special handling for Google's OAuth implementation.

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
      version: v0.2.1  # Use the latest version
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
| `scopes` | The OAuth 2.0 scopes to request | `["openid", "profile", "email"]` | `["openid", "email", "profile", "roles"]` |
| `logLevel` | Sets the logging verbosity | `info` | `debug`, `info`, `error` |
| `forceHTTPS` | Forces the use of HTTPS for all URLs | `true` | `true`, `false` |
| `rateLimit` | Sets the maximum number of requests per second | `100` | `500` |
| `excludedURLs` | Lists paths that bypass authentication | none | `["/health", "/metrics", "/public"]` |
| `allowedUserDomains` | Restricts access to specific email domains | none | `["company.com", "subsidiary.com"]` |
| `allowedRolesAndGroups` | Restricts access to users with specific roles or groups | none | `["admin", "developer"]` |
| `revocationURL` | The endpoint for revoking tokens | auto-discovered | `https://accounts.google.com/revoke` |
| `oidcEndSessionURL` | The provider's end session endpoint | auto-discovered | `https://accounts.google.com/logout` |
| `enablePKCE` | Enables PKCE (Proof Key for Code Exchange) for authorization code flow | `false` | `true`, `false` |
| `refreshGracePeriodSeconds` | Seconds before token expiry to attempt proactive refresh | `60` | `120` |
| `headers` | Custom HTTP headers with templates that can access OIDC claims and tokens | none | See "Templated Headers" section |

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
        - openid
        - email
        - profile
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
        - openid
        - email
        - profile
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
        - openid
        - email
        - profile
      allowedUserDomains:
        - company.com
        - subsidiary.com
```

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
        - openid
        - email
        - profile
        - roles     # Include this to get role information from the provider
      allowedRolesAndGroups:
        - admin
        - developer
```

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
        - openid
        - email
        - profile
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
        - openid
        - email
        - profile
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
        - openid
        - email
        - profile
        - roles
      headers:
        - name: "X-User-Email"
          value: "{{.Claims.email}}"
        - name: "X-User-ID"
          value: "{{.Claims.sub}}"
        - name: "Authorization"
          value: "Bearer {{.AccessToken}}"
        - name: "X-User-Roles"
          value: "{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}"
        - name: "X-Is-Admin"
          value: "{{if eq .Claims.role \"admin\"}}true{{else}}false{{end}}"
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
        - openid
        - email
        - profile
```

### Google OIDC Configuration Example

This example shows a configuration specifically tailored for Google OIDC:

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
      clientID: your-google-client-id.apps.googleusercontent.com # Replace with your Client ID
      clientSecret: your-google-client-secret                     # Replace with your Client Secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars # Replace with your key
      callbackURL: /oauth2/callback                             # Adjust if needed
      logoutURL: /oauth2/logout                                 # Optional: Adjust if needed
      scopes:
        - openid
        - email
        - profile
        # Note: DO NOT manually add offline_access scope for Google
        # The middleware automatically handles Google-specific requirements
      refreshGracePeriodSeconds: 300  # Optional: Start refresh 5 min before expiry (default 60)
      # Other optional parameters like allowedUserDomains, etc. can be added here
```

The middleware automatically detects Google as the provider and applies the necessary adjustments to ensure proper authentication and token refresh. See the [Google OAuth Fix](#google-oauth-compatibility-fix) section for details.

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
        - openid
        - email
        - profile
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
      - "--experimental.plugins.traefikoidc.version=v0.2.1"
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
            - openid
            - email
            - profile
          allowedUserDomains:
            - company.com
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
            - name: "X-User-Email"
              value: "{{.Claims.email}}"
            - name: "X-User-ID"
              value: "{{.Claims.sub}}"
            - name: "Authorization"
              value: "Bearer {{.AccessToken}}"
            - name: "X-User-Roles"
              value: "{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}"
```

## Advanced Configuration

### Session Management

The middleware uses encrypted cookies to manage user sessions. The `sessionEncryptionKey` must be at least 32 bytes long and should be kept secret.

### PKCE Support

The middleware supports PKCE (Proof Key for Code Exchange), which is an extension to the authorization code flow to prevent authorization code interception attacks. When enabled via the `enablePKCE` option, the middleware will generate a code verifier for each authentication request and derive a code challenge from it. The code verifier is stored in the user's session and sent during the token exchange process.

PKCE is recommended when:
- Your OIDC provider supports it (most modern providers do)
- You need an additional layer of security for the authorization code flow
- You're concerned about potential authorization code interception attacks

Note that not all OIDC providers support PKCE, so check your provider's documentation before enabling this feature.

### Session Duration and Token Refresh

This middleware aims to provide long-lived user sessions, typically up to 24 hours, by utilizing OIDC refresh tokens.

**How it works:**
- When a user authenticates, the middleware requests an access token and, if available, a refresh token from the OIDC provider.
- The access token usually has a short lifespan (e.g., 1 hour).
- Before the access token expires (controlled by `refreshGracePeriodSeconds`), the middleware uses the refresh token to obtain a new access token from the provider without requiring the user to log in again.
- This process repeats, allowing the session to remain valid for as long as the refresh token is valid (often 24 hours or more, depending on the provider).

**Provider-Specific Considerations (e.g., Google):**
- Some providers, like Google, issue short-lived access tokens (e.g., 1 hour) and require specific configurations for long-term sessions.
- To enable session extension beyond the initial token expiry with Google and similar providers, the middleware automatically includes the `offline_access` scope in the authentication request. This scope is necessary to obtain a refresh token.
- For Google specifically, the middleware also adds the `prompt=consent` parameter to the initial authorization request. This ensures Google issues a refresh token, which is crucial for extending the session.
- If a refresh attempt fails (e.g., the refresh token is revoked or expired), the user will be required to re-authenticate. The middleware includes enhanced error handling and logging for these scenarios.
- Ensure your OIDC provider is configured to issue refresh tokens and allows their use for extending sessions. Check your provider's documentation for details on refresh token validity periods.

### Google OAuth Compatibility Fix

The middleware includes a specific fix for Google's OAuth implementation, which differs from the standard OIDC specification in how it handles refresh tokens:

- **Issue**: Google does not support the standard `offline_access` scope for requesting refresh tokens and instead requires special parameters.
  
- **Automatic Solution**: The middleware detects Google as the provider based on the issuer URL and:
  - Uses `access_type=offline` query parameter instead of the `offline_access` scope
  - Adds `prompt=consent` to ensure refresh tokens are consistently issued
  - Properly handles token refresh with Google's implementation

You do not need any special configuration to use Google OAuth - just set `providerURL` to `https://accounts.google.com` and the middleware will automatically apply the proper parameters.

For detailed information on the Google OAuth fix, see the [dedicated documentation](docs/google-oauth-fix.md).

### Token Caching and Blacklisting

The middleware automatically caches validated tokens to improve performance and maintains a blacklist of revoked tokens.
### Templated Headers

The middleware supports setting custom HTTP headers with values templated from OIDC claims and tokens. This allows you to pass authentication information to downstream services in a flexible, customized format.

Templates can access the following variables:
- `{{.Claims.field}}` - Access individual claims from the ID token (e.g., `{{.Claims.email}}`, `{{.Claims.sub}}`)
- `{{.AccessToken}}` - The raw access token string
- `{{.IdToken}}` - The raw ID token string (same as AccessToken in most configurations)
- `{{.RefreshToken}}` - The raw refresh token string

**Example configuration:**
```yaml
headers:
  - name: "X-User-Email"
    value: "{{.Claims.email}}"
  - name: "X-User-ID"
    value: "{{.Claims.sub}}"
  - name: "Authorization"
    value: "Bearer {{.AccessToken}}"
  - name: "X-User-Name"
    value: "{{.Claims.given_name}} {{.Claims.family_name}}"
```

**Advanced template examples:**

Conditional logic:
```yaml
headers:
  - name: "X-Is-Admin"
    value: "{{if eq .Claims.role \"admin\"}}true{{else}}false{{end}}"
```

Array handling:
```yaml
headers:
  - name: "X-User-Roles"
    value: "{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}"
```

**Notes:**
- Variable names are case-sensitive (use `.Claims`, not `.claims`)
- Missing claims will result in `<no value>` in the header value
- The middleware validates templates during startup and logs errors for invalid templates

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
6. **Google sessions expire after ~1 hour**: If using Google as the OIDC provider and sessions expire prematurely (around 1 hour instead of longer), ensure:
   - Do NOT manually add the `offline_access` scope. Google rejects this scope as invalid.
   - The middleware automatically applies the required Google parameters (`access_type=offline` and `prompt=consent`).
   - Your Google Cloud OAuth consent screen is set to "External" and "Production" mode. "Testing" mode often limits refresh token validity.
   - Verify you're using a version of the middleware that includes the Google OAuth compatibility fix.
   - For more details, see the [Google OAuth Compatibility Fix](#google-oauth-compatibility-fix) section or the [detailed documentation](docs/google-oauth-fix.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
