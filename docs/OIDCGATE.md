# oidcgate — standalone OIDC forward-auth daemon

`oidcgate` is a single binary that exposes the same OIDC middleware that
powers the Traefik plugin as a forward-auth daemon for nginx, Caddy,
Traefik ForwardAuth, HAProxy, and Envoy ext_authz_http.

## Build

```bash
go build -o oidcgate ./cmd/oidcgate
```

## Run

```bash
./oidcgate --config /etc/oidcgate/config.yaml
```

## Config

YAML, mirroring the existing Traefik plugin schema with three extra keys:

```yaml
listen: ":8080"
authPath: "/oauth2/auth"   # default; nginx auth_request subrequest target
startPath: "/oauth2/start" # default; visible sign-in endpoint
providerURL: "https://accounts.google.com"
clientID: "your-client-id"
clientSecret: "your-client-secret"
sessionEncryptionKey: "64-hex-bytes"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
# ... any other traefikoidc Config field works here verbatim
```

Secrets can be overridden via environment variables:
`OIDCGATE_CLIENT_SECRET`, `OIDCGATE_SESSION_ENCRYPTION_KEY`,
`OIDCGATE_CLIENT_ID`, etc.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/oauth2/auth` | GET | Silent probe — `200` if authenticated, `401` if not |
| `/oauth2/start` | GET | Visible sign-in — `302` to IdP, accepts `?rd=` for return target |
| `/oauth2/callback` | GET | IdP callback |
| `/oauth2/logout` | GET/POST | Session terminate |
| `/healthz` | GET | Liveness — `200` while process is alive |
| `/readyz` | GET | Readiness — `200` after first metadata discovery, else `503` |

## nginx

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
    proxy_set_header X-Forwarded-Host $host;
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

## Caddy

```
example.com {
    forward_auth oidcgate:8080 {
        uri /oauth2/auth
        copy_headers X-Forwarded-User X-Forwarded-Email
    }
    handle /oauth2/* {
        reverse_proxy oidcgate:8080
    }
    reverse_proxy backend:3000
}
```

## Traefik ForwardAuth

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
