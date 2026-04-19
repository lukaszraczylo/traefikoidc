# Dynamic Client Registration (RFC 7591)

The middleware can register itself with an OIDC provider at startup instead of
using a pre-provisioned `clientID` / `clientSecret`. Useful for multi-tenant
deployments, self-service integrations, and ephemeral environments.

## How it works

1. Middleware reads `registration_endpoint` from `.well-known/openid-configuration`.
2. If `clientID` is empty, it `POST`s `clientMetadata` to the registration endpoint.
3. Returned `client_id` / `client_secret` are cached, optionally persisted.
4. Subsequent requests use the registered credentials.

For multi-replica deployments, set `storageBackend: redis` so all replicas
share one client and avoid registration races.

## Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-dcr
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://your-oidc-provider.com
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      dynamicClientRegistration:
        enabled: true
        persistCredentials: true
        storageBackend: redis        # file | redis | auto
        initialAccessToken: ""        # optional, for protected endpoints
        registrationEndpoint: ""      # optional, override discovery
        credentialsFile: /tmp/oidc-client-credentials.json
        redisKeyPrefix: "dcr:creds:"
        clientMetadata:
          redirect_uris:
            - https://app.example.com/oauth2/callback
          client_name: My Application
          application_type: web
          grant_types: [authorization_code, refresh_token]
          response_types: [code]
          token_endpoint_auth_method: client_secret_basic
          contacts: [admin@example.com]
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `enabled` | `false` | Enable DCR. |
| `persistCredentials` | `false` | Save returned credentials for reuse across restarts. |
| `storageBackend` | `auto` | `file`, `redis`, or `auto` (Redis if available, else file). |
| `credentialsFile` | `/tmp/oidc-client-credentials.json` | Path for file-backed storage. Mode `0600`. |
| `redisKeyPrefix` | (none — set explicitly) | Key prefix for Redis-backed storage. The code does not inject a default; if unset, keys have no prefix. `dcr:creds:` is a sensible convention. |
| `registrationEndpoint` | discovered | Override the discovered endpoint. |
| `initialAccessToken` | none | Bearer token for protected registration endpoints. |
| `clientMetadata.redirect_uris` | required | Callback URIs for the OAuth flow. |
| `clientMetadata.client_name` | none | Human-readable client name. |
| `clientMetadata.application_type` | `web` | `web` or `native`. |
| `clientMetadata.grant_types` | `[authorization_code, refresh_token]` | OAuth grant types. |
| `clientMetadata.response_types` | `[code]` | OAuth response types. |
| `clientMetadata.token_endpoint_auth_method` | `client_secret_basic` | `client_secret_basic`, `client_secret_post`, or `none`. |
| `clientMetadata.scope` | none | Space-separated scopes. |
| `clientMetadata.contacts` | none | Admin email addresses. |
| `clientMetadata.logo_uri` | none | Logo URL for consent screens. |
| `clientMetadata.client_uri` | none | Client homepage URL. |
| `clientMetadata.policy_uri` | none | Privacy policy URL. |
| `clientMetadata.tos_uri` | none | Terms of service URL. |

## Provider support

The middleware does not gate DCR by provider — if the provider exposes a
`registration_endpoint` in its discovery document (or you set
`registrationEndpoint` explicitly), DCR will attempt registration. The table
below is informational guidance based on each provider's published support.

| Provider | DCR | Notes |
|----------|-----|-------|
| Keycloak | Yes | Enable in realm settings. |
| Auth0 | Yes | Requires Management API token. |
| Okta | Yes | Enable Dynamic Client Registration in admin console. |
| Azure AD | Limited | Use App Registration API instead. |
| Google | No | Manual registration required. |
| AWS Cognito | No | Manual registration required. |

## Security notes

- Registration endpoints must be HTTPS (loopback excepted for local dev).
- Use `initialAccessToken` in production to gate registration.
- File-backed credentials use `0600`; protect the mount path.
- The plugin marks credentials invalid when within ~5 min of `client_secret_expires_at` but does **not** automatically re-register. If your provider sets a non-zero expiry, schedule manual rotation (delete the credentials file or Redis entry, restart) before that time.
