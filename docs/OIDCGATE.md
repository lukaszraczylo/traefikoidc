# oidcgate — standalone OIDC forward-auth daemon

`oidcgate` is a single binary that exposes the same OIDC middleware that
powers the Traefik plugin as a forward-auth daemon for nginx, Caddy,
Traefik ForwardAuth, HAProxy, and Envoy `ext_authz_http`.

## Table of contents

- [Build](#build)
- [Run](#run)
- [Configuration](#configuration)
  - [YAML file](#yaml-file)
  - [Environment-variable overrides](#environment-variable-overrides)
- [Endpoints](#endpoints)
- [Reverse-proxy snippets](#reverse-proxy-snippets)
  - [nginx (`auth_request`)](#nginx-auth_request)
  - [Caddy (`forward_auth`)](#caddy-forward_auth)
  - [Traefik (`ForwardAuth`)](#traefik-forwardauth)
  - [HAProxy](#haproxy)
  - [Envoy (`ext_authz_http`)](#envoy-ext_authz_http)
- [Security posture](#security-posture)
- [Bearer-token (M2M) auth on the same daemon](#bearer-token-m2m-auth-on-the-same-daemon)
- [Operational guidance](#operational-guidance)
- [Debugging](#debugging)

## Build

```bash
go build -o oidcgate ./cmd/oidcgate
```

## Run

```bash
./oidcgate --config /etc/oidcgate/config.yaml
```

The daemon parses `--config`, loads YAML, applies any `OIDCGATE_*` env-var
overrides, validates the result, and binds to `listen`. On SIGINT/SIGTERM it
calls `http.Server.Shutdown` with a 15s deadline, draining in-flight requests.

## Configuration

### YAML file

The OIDC subtree of the config maps 1:1 onto the [`traefikoidc.Config`](CONFIGURATION.md)
struct — every field documented under "Configuration Reference" works here
verbatim. Three extra top-level keys configure the daemon itself:

| Key | Default | Purpose |
|---|---|---|
| `listen` | _required_ | TCP address (e.g. `:8080`, `127.0.0.1:8080`). |
| `authPath` | `/oauth2/auth` | Silent-probe endpoint (used by nginx `auth_request`). |
| `startPath` | `/oauth2/start` | Visible sign-in endpoint. |

Minimal example (see [`examples/oidcgate.yaml`](../examples/oidcgate.yaml)):

```yaml
listen: ":8080"
providerURL: "https://accounts.google.com"
clientID: "your-client-id"
clientSecret: "your-client-secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
```

Nested structs (`redis:`, `securityHeaders:`, `dynamicClientRegistration:`)
round-trip cleanly through YAML — same shape as in `.traefik.yml`.

### Environment-variable overrides

Any of the following scalar fields can be overridden at runtime by an
`OIDCGATE_<UPPER_SNAKE_CASE>` environment variable. The env var wins over
the YAML value when set and non-empty. Intended for secret injection
(K8s `valueFrom.secretKeyRef`, systemd `EnvironmentFile=`, etc.).

| YAML key | Env var |
|---|---|
| `listen` | `OIDCGATE_LISTEN` |
| `authPath` | `OIDCGATE_AUTH_PATH` |
| `startPath` | `OIDCGATE_START_PATH` |
| `providerURL` | `OIDCGATE_PROVIDER_URL` |
| `clientID` | `OIDCGATE_CLIENT_ID` |
| `clientSecret` | `OIDCGATE_CLIENT_SECRET` |
| `audience` | `OIDCGATE_AUDIENCE` |
| `callbackURL` | `OIDCGATE_CALLBACK_URL` |
| `logoutURL` | `OIDCGATE_LOGOUT_URL` |
| `postLogoutRedirectURI` | `OIDCGATE_POST_LOGOUT_REDIRECT_URI` |
| `sessionEncryptionKey` | `OIDCGATE_SESSION_ENCRYPTION_KEY` |
| `cookiePrefix` | `OIDCGATE_COOKIE_PREFIX` |
| `cookieDomain` | `OIDCGATE_COOKIE_DOMAIN` |
| `logLevel` | `OIDCGATE_LOG_LEVEL` |
| `revocationURL` | `OIDCGATE_REVOCATION_URL` |
| `oidcEndSessionURL` | `OIDCGATE_OIDC_END_SESSION_URL` |
| `userIdentifierClaim` | `OIDCGATE_USER_IDENTIFIER_CLAIM` |
| `groupClaimName` | `OIDCGATE_GROUP_CLAIM_NAME` |
| `roleClaimName` | `OIDCGATE_ROLE_CLAIM_NAME` |
| `clientAuthMethod` | `OIDCGATE_CLIENT_AUTH_METHOD` |
| `clientAssertionPrivateKey` | `OIDCGATE_CLIENT_ASSERTION_PRIVATE_KEY` |
| `clientAssertionKeyPath` | `OIDCGATE_CLIENT_ASSERTION_KEY_PATH` |
| `clientAssertionKeyID` | `OIDCGATE_CLIENT_ASSERTION_KEY_ID` |
| `clientAssertionAlg` | `OIDCGATE_CLIENT_ASSERTION_ALG` |
| `caCertPath` | `OIDCGATE_CA_CERT_PATH` |
| `caCertPEM` | `OIDCGATE_CA_CERT_PEM` |

Nested-struct fields (Redis, security headers, DCR) are YAML-only — set
them in the config file, not via env.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/oauth2/auth` | GET | Silent probe — `200` if authenticated, `401` if not. Never returns `302`; the middleware's redirect-to-IdP is rewritten in-flight to `401` with the original `Location` carried as `X-Auth-Redirect`. |
| `/oauth2/start` | GET | Visible sign-in — `302` to the IdP authorize URL. Accepts `?rd=<safe-path>` (or honours `X-Forwarded-Uri`) for the post-login redirect target. |
| `/oauth2/callback` | GET | IdP `code`+`state` exchange. Path is configurable via `callbackURL`. |
| `/oauth2/logout` | GET/POST | Terminates the session. Path is configurable via `logoutURL`. Honours `oidcEndSessionURL` for RP-initiated logout. |
| `/healthz` | GET | Liveness — `200` while the process is alive. |
| `/readyz` | GET | Readiness — `200` once the OIDC discovery document has been fetched, otherwise `503`. |

## Reverse-proxy snippets

### nginx (`auth_request`)

```nginx
location = /oauth2/auth {
    internal;
    proxy_pass              http://oidcgate:8080;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
    proxy_set_header        X-Forwarded-Uri $request_uri;
    proxy_set_header        X-Forwarded-Host $host;
    proxy_set_header        X-Forwarded-Proto $scheme;
}
location @oidc_signin {
    return 302 /oauth2/start?rd=$scheme://$host$request_uri;
}
location /oauth2/ {
    proxy_pass       http://oidcgate:8080;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
location / {
    auth_request           /oauth2/auth;
    error_page             401 = @oidc_signin;
    auth_request_set       $user  $upstream_http_x_forwarded_user;
    auth_request_set       $email $upstream_http_x_forwarded_email;
    proxy_set_header       X-Forwarded-User  $user;
    proxy_set_header       X-Forwarded-Email $email;
    proxy_pass             http://backend;
}
```

### Caddy (`forward_auth`)

```caddyfile
example.com {
    forward_auth oidcgate:8080 {
        uri /oauth2/auth
        copy_headers X-Forwarded-User X-Forwarded-Email
        @denied status 401
        handle_response @denied {
            redir /oauth2/start?rd={http.request.uri} 302
        }
    }
    handle /oauth2/* {
        reverse_proxy oidcgate:8080
    }
    reverse_proxy backend:3000
}
```

### Traefik (`ForwardAuth`)

```yaml
http:
  middlewares:
    oidcgate:
      forwardAuth:
        address: "http://oidcgate:8080/oauth2/auth"
        authResponseHeaders:
          - X-Forwarded-User
          - X-Forwarded-Email
```

Traefik can follow the `X-Auth-Redirect` value via a chained `redirectScheme`
middleware, or you can configure the upstream router to redirect `401` →
`/oauth2/start` directly.

### HAProxy

```haproxy
frontend fe_https
    bind *:443 ssl crt /etc/haproxy/certs/site.pem
    http-request set-var(req.orig_uri) path
    http-request send-spoe-group oidc auth-check  # or use lua/SPOE; simplest is the lua snippet below

    # The simpler pattern: dispatch /oauth2/* to oidcgate, everything else
    # goes through a Lua filter that issues a sub-request to /oauth2/auth.
    acl is_oidc_endpoint path_beg /oauth2/
    use_backend be_oidcgate if is_oidc_endpoint
    default_backend be_app

backend be_oidcgate
    server oidcgate1 oidcgate:8080

backend be_app
    server app1 backend:3000
```

HAProxy does not have a first-class `auth_request` equivalent in pure
config — the canonical patterns are SPOE (Stream Processing Offload Engine),
a Lua filter that issues `/oauth2/auth` and reads the response, or a
sidecar that does the dance. Reach for SPOE for high-throughput
production; Lua is simpler for low-volume.

### Envoy (`ext_authz_http`)

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      http_service:
        server_uri:
          uri: http://oidcgate:8080
          cluster: oidcgate
          timeout: 2s
        path_prefix: /oauth2/auth
        authorization_request:
          allowed_headers:
            patterns:
              - exact: cookie
              - exact: authorization
              - prefix: x-forwarded-
        authorization_response:
          allowed_upstream_headers:
            patterns:
              - exact: x-forwarded-user
              - exact: x-forwarded-email
          allowed_client_headers:
            patterns:
              - exact: x-auth-redirect
              - exact: set-cookie
```

On `401`, the `X-Auth-Redirect` header is surfaced to the downstream client
via `allowed_client_headers`. A small Envoy `router` filter or
`local_reply_config` rule can convert that into a browser-facing `302`
redirect to `/oauth2/start`.

## Security posture

- **`X-Forwarded-Uri` is sanitised.** The daemon forces
  `TrustForwardedURI=true` so the middleware honours `X-Forwarded-Uri` for
  the post-login redirect target. To prevent open redirects (CWE-601),
  the value is rejected unless it is a safe same-origin path: must start
  with `/`, must NOT start with `//` (protocol-relative), and must have
  no scheme or host after parsing. Absolute URLs or anything that could
  redirect off-origin falls through to `req.URL.RequestURI()`.

- **`excludedURLs` cannot bypass the daemon's own paths.** At config
  load, the loader rejects any `excludedURLs` entry that is a prefix of
  `authPath`, `startPath`, `callbackURL`, `logoutURL`, or the internal
  sentinel path. A misconfiguration like `excludedURLs: ["/"]` (common
  "allow all then add auth selectively" mistake) is rejected at startup
  with a descriptive error.

- **`callbackURL` and `logoutURL` must be paths.** Absolute URLs are
  rejected at config load — both because `http.ServeMux.Handle` panics
  on non-`/` patterns and because the middleware's path-match would
  silently fail.

- **`listen` is required.** Empty or missing `listen` is rejected at
  startup rather than failing later at `net.Listen`.

- **Secrets via env vars.** `clientSecret` and `sessionEncryptionKey`
  can be supplied via env vars instead of YAML so they don't end up on
  disk if you use a secret manager.

## Bearer-token (M2M) auth on the same daemon

oidcgate uses the full `traefikoidc.Config` shape, so the bearer-token
M2M auth path documented in [`BEARER_AUTH.md`](BEARER_AUTH.md) works
out of the box. Add to your YAML:

```yaml
enableBearerAuth: true
audience: "https://api.example.com"
bearerIdentifierClaim: "sub"
# stripAuthorizationHeader: true   # default
# bearerOverridesCookie: false     # default — cookie wins on collision
```

With this set, the daemon accepts both:
- Browser users hitting `/oauth2/auth` → cookie session flow.
- API clients calling the protected backend with `Authorization: Bearer <jwt>`
  → bearer validation, principal headers, no session.

The bearer path doesn't go through `/oauth2/auth` separately — it's
applied by the middleware on every request the daemon sees, before the
cookie session check. See [BEARER_AUTH.md](BEARER_AUTH.md) for the full
threat model, identifier sanitisation rules, and failure-response
matrix.

## Operational guidance

- **Run behind a fronting proxy on a private network.** The daemon does
  not terminate TLS. Put it on a localhost socket or a private subnet
  reachable only from your nginx/Caddy/Traefik/HAProxy/Envoy.
- **`/healthz` and `/readyz` are unauthenticated** — correct for
  Kubernetes liveness/readiness probes, but **do not expose them past a
  load balancer**. Restrict via an ACL: nginx `allow 10.0.0.0/8; deny
  all;`, Caddy `@health remote_ip 10.0.0.0/8`, k8s NetworkPolicy, or
  your CNI of choice.
- **Multi-replica deployments** need a shared session store. Enable the
  `redis:` block in the config (see [`docs/REDIS.md`](REDIS.md)) so
  sessions survive a hop between replicas.
- **No built-in Prometheus metrics yet.** If you need request-level
  visibility, take it from your fronting proxy's access logs — both
  nginx and Envoy can tag `auth_request` / `ext_authz` outcomes.
- **Logs are minimal by default.** Set `logLevel: debug` while
  bringing up a new deployment; raise to `info` (default) or higher
  once stable. Debug logs include path-match decisions and metadata
  refresh outcomes.
- **Graceful shutdown is 15s.** SIGINT or SIGTERM triggers
  `http.Server.Shutdown(ctx)` with a 15-second deadline; in-flight
  requests are allowed to complete. If your orchestrator's grace
  period is shorter, requests can be cut mid-flight.

## Debugging

- **Requests appear as `/__oidcgate_protected__` in middleware debug
  logs.** This is the internal sentinel path used when `/oauth2/auth`
  and `/oauth2/start` delegate into the traefikoidc middleware. The
  upstream client never sees it; it only shows up in the middleware's
  own `Debugf` output when `logLevel: debug` is set.

- **`/oauth2/auth` returns `401` with `X-Auth-Redirect` header on
  unauthenticated requests.** This is the deliberate translation of the
  middleware's `302` to make nginx `auth_request` work. The browser is
  redirected via the fronting proxy's `error_page 401 = @oidc_signin;`
  pattern, not by following the daemon's response directly.

- **`/readyz` stays `503` after startup.** The middleware fetches the
  OIDC discovery document lazily on first request, so `/readyz` returns
  `503` until at least one request has triggered metadata discovery.
  Hit `/oauth2/auth` once after startup to warm it up — many K8s
  setups achieve the same effect because the liveness probe already
  goes through the proxy chain.

- **Cookie/session diagnostics.** With `logLevel: debug` the middleware
  logs which session manager was selected (in-memory vs Redis), whether
  cookies decrypted successfully, and the JWT validation outcome.

- **Open-redirect rejections are silent.** When the daemon ignores an
  unsafe `X-Forwarded-Uri` value, it falls back to `req.URL.RequestURI()`
  without logging. This is intentional (no recon signal) — if a user
  reports "I keep landing on the wrong page after login", inspect
  whether the upstream proxy is forwarding a non-canonical
  `X-Forwarded-Uri` value.
