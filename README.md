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

The middleware has been tested with Auth0 and Logto, but should work with any standard OIDC provider.

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

### Token Caching and Blacklisting

The middleware automatically caches validated tokens to improve performance and maintains a blacklist of revoked tokens.

### Headers Set for Downstream Services

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
