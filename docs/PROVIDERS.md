# OIDC Provider Configuration Guide

Configuration reference for each supported OIDC provider.

## Table of Contents

- [Provider Support Matrix](#provider-support-matrix)
- [Google](#google)
- [Microsoft Azure AD](#microsoft-azure-ad)
- [Auth0](#auth0)
- [Okta](#okta)
- [Keycloak](#keycloak)
- [AWS Cognito](#aws-cognito)
- [GitLab](#gitlab)
- [GitHub](#github)
- [Generic OIDC](#generic-oidc)
- [Automatic Scope Filtering](#automatic-scope-filtering)

---

## Provider Support Matrix

| Provider | OIDC Support | Refresh Tokens | Auto-Detection | ID Tokens |
|----------|-------------|----------------|----------------|-----------|
| Google | Full | Yes | `accounts.google.com` | Yes |
| Azure AD | Full | Yes | `login.microsoftonline.com` | Yes |
| Auth0 | Full | Yes | `*.auth0.com` | Yes |
| Okta | Full | Yes | `*.okta.com` | Yes |
| Keycloak | Full | Yes | `/auth/realms/` path | Yes |
| AWS Cognito | Full | Yes | `cognito-idp.*.amazonaws.com` | Yes |
| GitLab | Full | Yes | `gitlab.com` | Yes |
| GitHub | OAuth 2.0 Only | No | `github.com` | No |
| Generic | Full | Yes | Any OIDC endpoint | Yes |

---

## Google

### Provider URL

```yaml
providerURL: "https://accounts.google.com"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-google
spec:
  plugin:
    traefikoidc:
      providerURL: "https://accounts.google.com"
      clientID: "your-id.apps.googleusercontent.com"
      clientSecret: "your-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - email
        - profile
      allowedUserDomains:
        - "your-gsuite-domain.com"  # Optional: Workspace restriction
      forceHttps: true
      enablePkce: true
```

### Google-Specific Features

- **Automatic offline access**: Middleware adds `access_type=offline` and `prompt=consent`
- **Scope filtering**: Automatically removes unsupported `offline_access` scope
- **Workspace domains**: Restrict to specific Google Workspace domains via `hd` claim

### Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Navigate to APIs & Services > Credentials
4. Create OAuth 2.0 Client ID (Web application)
5. Add authorized redirect URI: `https://your-domain.com/oauth2/callback`
6. Configure OAuth consent screen (must be "Published" for production)

---

## Microsoft Azure AD

### Provider URL

```yaml
# Single tenant
providerURL: "https://login.microsoftonline.com/{tenant-id}/v2.0"

# Multi-tenant
providerURL: "https://login.microsoftonline.com/common/v2.0"
```

### Basic Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-azure
spec:
  plugin:
    traefikoidc:
      providerURL: "https://login.microsoftonline.com/common/v2.0"
      clientID: "your-azure-client-id"
      clientSecret: "your-azure-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        - offline_access
      allowedRolesAndGroups:
        - "App.Users"
        - "Admin.Group"
      forceHttps: true
```

### With Application ID URI (API Access)

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-azure-api
spec:
  plugin:
    traefikoidc:
      providerURL: "https://login.microsoftonline.com/common/v2.0"
      clientID: "your-azure-client-id"
      clientSecret: "your-azure-client-secret"
      audience: "api://your-azure-client-id"  # Application ID URI
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      forceHttps: true
```

### Users Without Email

```yaml
userIdentifierClaim: sub  # Options: sub, oid, upn, preferred_username
allowedUsers:
  - "user-object-id-1"
  - "user-object-id-2"
```

### Azure AD Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Create new registration
4. Add redirect URI: `https://your-domain.com/oauth2/callback`
5. Create client secret in Certificates & secrets
6. Configure Token Configuration for group claims

---

## Auth0

### Provider URL

```yaml
providerURL: "https://your-domain.auth0.com"
```

### Basic Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth0
spec:
  plugin:
    traefikoidc:
      providerURL: "https://your-domain.auth0.com"
      clientID: "your-auth0-client-id"
      clientSecret: "your-auth0-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        - offline_access
      postLogoutRedirectUri: "https://your-app.com"
      forceHttps: true
      enablePkce: true
```

### With Custom API Audience

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-auth0-api
spec:
  plugin:
    traefikoidc:
      providerURL: "https://your-domain.auth0.com"
      clientID: "your-auth0-client-id"
      clientSecret: "your-auth0-client-secret"
      audience: "https://api.your-domain.com"  # API identifier
      strictAudienceValidation: true
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      roleClaimName: "https://your-app.com/roles"  # Namespaced claim
      groupClaimName: "https://your-app.com/groups"
      allowedRolesAndGroups:
        - admin
        - editor
```

### Auth0 Action for Custom Claims

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://your-app.com/';
  if (event.authorization) {
    api.idToken.setCustomClaim(namespace + 'roles', event.authorization.roles);
    api.idToken.setCustomClaim('email', event.user.email);
  }
};
```

### Auth0 Setup

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Create Regular Web Application
3. Configure Allowed Callback URLs: `https://your-domain.com/oauth2/callback`
4. Configure Allowed Logout URLs: `https://your-domain.com/oauth2/logout`
5. Enable OIDC Conformant in Advanced Settings
6. Create API in APIs section for custom audiences

See [AUTH0_AUDIENCE_GUIDE.md](AUTH0_AUDIENCE_GUIDE.md) for detailed audience configuration.

---

## Okta

### Provider URL

```yaml
providerURL: "https://your-domain.okta.com"
# Or with custom authorization server:
providerURL: "https://your-domain.okta.com/oauth2/default"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-okta
spec:
  plugin:
    traefikoidc:
      providerURL: "https://your-domain.okta.com"
      clientID: "your-okta-client-id"
      clientSecret: "your-okta-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        - groups
        - offline_access
      allowedRolesAndGroups:
        - admin
        - "Everyone"
      forceHttps: true
      enablePkce: true
```

### Okta Setup

1. Access Okta Admin Console
2. Go to Applications > Create App Integration
3. Select OIDC - OpenID Connect > Web Application
4. Configure Sign-in redirect URIs: `https://your-domain.com/oauth2/callback`
5. Configure Sign-out redirect URIs: `https://your-domain.com/oauth2/logout`
6. Enable Authorization Code and Refresh Token grant types
7. Configure Groups claim in authorization server

---

## Keycloak

### Provider URL

```yaml
providerURL: "https://keycloak.your-domain.com/realms/{realm-name}"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-keycloak
spec:
  plugin:
    traefikoidc:
      providerURL: "https://keycloak.company.com/realms/your-realm"
      clientID: "your-keycloak-client-id"
      clientSecret: "your-keycloak-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        - roles
        - groups
        - offline_access
      allowedRolesAndGroups:
        - admin
        - editor
      forceHttps: true
      enablePkce: true
```

### Internal Network Deployment

For private IP addresses (Docker networks, Kubernetes):

```yaml
providerURL: "https://192.168.1.100:8443/realms/your-realm"
allowPrivateIPAddresses: true  # Required for private IPs
```

### Keycloak Client Setup

1. Access Keycloak Admin Console
2. Select your realm
3. Go to Clients > Create client
4. Set Client Protocol: openid-connect
5. Set Access Type: confidential
6. Add Valid Redirect URIs: `https://your-domain.com/oauth2/callback`
7. Generate client secret in Credentials tab
8. Configure mappers to add claims to ID Token:
   - Email: User Property mapper with "Add to ID token" enabled
   - Roles: User Client Role mapper with "Add to ID token" enabled
   - Groups: Group Membership mapper with "Add to ID token" enabled

---

## AWS Cognito

### Provider URL

```yaml
providerURL: "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-cognito
spec:
  plugin:
    traefikoidc:
      providerURL: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABCDEF123"
      clientID: "your-cognito-client-id"
      clientSecret: "your-cognito-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        - aws.cognito.signin.user.admin
      allowedRolesAndGroups:
        - admin
        - users
      forceHttps: true
```

### AWS Cognito Setup

1. Create Cognito User Pool
2. Create App Client with OIDC scopes
3. Configure App Client settings:
   - Callback URLs: `https://your-domain.com/oauth2/callback`
   - Sign out URLs: `https://your-domain.com/oauth2/logout`
   - OAuth flows: Authorization code grant
4. Configure hosted UI domain (optional)
5. Set up groups for role-based access

---

## GitLab

### Provider URL

```yaml
# GitLab.com
providerURL: "https://gitlab.com"

# Self-hosted
providerURL: "https://gitlab.your-company.com"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-gitlab
spec:
  plugin:
    traefikoidc:
      providerURL: "https://gitlab.com"
      clientID: "your-gitlab-application-id"
      clientSecret: "your-gitlab-application-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
        # Note: GitLab doesn't require offline_access scope
        # Refresh tokens are issued automatically with openid
      allowedRolesAndGroups:
        - developers
        - maintainers
      forceHttps: true
      enablePkce: true
```

### GitLab Setup

1. Go to GitLab Settings > Applications
2. Create new application
3. Add scopes: `openid`, `profile`, `email`
4. Set redirect URI: `https://your-domain.com/oauth2/callback`
5. Save and note Application ID and Secret

---

## GitHub

### Provider URL

```yaml
providerURL: "https://github.com"
```

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oauth-github
spec:
  plugin:
    traefikoidc:
      providerURL: "https://github.com/login/oauth"
      clientID: "your-github-client-id"
      clientSecret: "your-github-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - user:email
        - read:user
      allowedUsers:
        - "github-username"
      forceHttps: true
```

### Limitations

- **OAuth 2.0 only** - Not OpenID Connect
- **No ID tokens** - Only access tokens for API calls
- **No refresh tokens** - Users must re-authenticate on expiry
- **No standard claims** - User info requires API calls

Use GitHub only for API access, not for user authentication with claims.

### GitHub Setup

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create new OAuth App
3. Set Authorization callback URL: `https://your-domain.com/oauth2/callback`
4. Note Client ID and generate Client Secret

---

## Generic OIDC

For any OIDC-compliant provider not listed above.

### Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-generic
spec:
  plugin:
    traefikoidc:
      providerURL: "https://oidc.your-provider.com"
      clientID: "your-client-id"
      clientSecret: "your-client-secret"
      callbackURL: "/oauth2/callback"
      sessionEncryptionKey: "your-32-char-encryption-key-here"
      scopes:
        - openid
        - profile
        - email
      forceHttps: true
      enablePkce: true
```

### Requirements

- Provider must expose `.well-known/openid-configuration` endpoint
- Must support authorization code flow
- ID tokens must contain required claims (email, sub, etc.)

---

## Automatic Scope Filtering

The middleware automatically filters OAuth scopes based on the provider's declared capabilities.

### How It Works

1. Fetches provider's `.well-known/openid-configuration`
2. Extracts `scopes_supported` field
3. Filters requested scopes to only include supported ones
4. Falls back to all requested scopes if provider doesn't declare supported scopes

### Example: Self-Hosted GitLab

Self-hosted GitLab may reject `offline_access` scope:

```yaml
scopes:
  - openid
  - profile
  - email
  - offline_access  # Will be automatically filtered out if unsupported
```

The middleware will:
1. Read GitLab's discovery document
2. Detect `offline_access` is NOT in `scopes_supported`
3. Filter it out automatically
4. Authentication succeeds

### Logging

```
INFO: ScopeFilter: Filtered unsupported scopes: [offline_access]
DEBUG: ScopeFilter: Final filtered scopes: [openid profile email]
```

### Troubleshooting

If a provider rejects scopes even after filtering:
1. Check the provider's discovery document: `curl https://provider/.well-known/openid-configuration`
2. Use `overrideScopes: true` with only supported scopes
3. Review middleware debug logs for filtering decisions
