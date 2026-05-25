# oidcgate — Standalone OIDC Forward-Auth Daemon (Tier 1)

**Date:** 2026-05-19
**Status:** Design approved, pending implementation plan
**Scope:** Tier 1 only — forward-auth daemon. No reverse-proxy mode, no TLS termination, no metrics, no multi-tenancy.

## Goal

Provide a standalone Go binary that exposes the existing `traefikoidc` OIDC middleware as a forward-auth daemon callable from nginx (`auth_request`), Caddy (`forward_auth`), Traefik (`ForwardAuth`), HAProxy, and Envoy (`ext_authz_http`). The library's public surface is **additive only**: no existing exported function signature changes; one optional `Config` field (`TrustForwardedURI`) and one new read-only accessor on `*TraefikOidc` are added. Existing Traefik plugin users see no behavior change unless they opt in to the new field.

## Non-Goals

- Reverse-proxy mode (Tier 2 — separate effort if requested).
- TLS termination inside the daemon.
- Built-in Prometheus metrics.
- Multi-tenant routing (one binary serves one OIDC client config).
- oauth2-proxy CLI/flag compatibility.
- Docker image or goreleaser publishing as part of Tier 1.

## Architecture

### File layout

```
github.com/lukaszraczylo/traefikoidc          (library, unchanged)
├── main.go                                    (existing New/NewWithContext)
├── middleware.go                              (existing ServeHTTP + ~10 LoC patch)
└── cmd/
    └── oidcgate/
        ├── main.go                            (entrypoint, flags, signal handling)
        ├── config.go                          (YAML loader + env-var override walker)
        ├── server.go                          (http.ServeMux wiring, listen loop)
        ├── endpoints.go                       (auth/start/callback/logout handlers)
        ├── success.go                         (synthetic success handler used as `next`)
        ├── interceptor.go                     (302→401 response-writer for /oauth2/auth)
        ├── health.go                          (/healthz, /readyz)
        ├── config_test.go
        ├── endpoints_test.go
        └── interceptor_test.go
```

### Process model

Single binary, single `*TraefikOidc` instance built at boot from YAML config, served on one listener port. Health endpoints on the same listener. Graceful shutdown on `SIGINT`/`SIGTERM` via `srv.Shutdown(ctx)` with a 15s deadline, after which context cancellation propagates into the existing goroutine manager.

## Endpoint Contract

All four endpoints share the listener. Paths are configurable; defaults shown.

| Endpoint | Default path | Method | Contract |
|---|---|---|---|
| **Auth probe** | `/oauth2/auth` | GET | Silent. `200 OK` + injected headers on success. `401` on failure (never `302`). Consumed by nginx `auth_request`, Traefik ForwardAuth, Caddy `forward_auth`, Envoy ext_authz_http. |
| **Sign-in** | `/oauth2/start` | GET | Always `302` to IdP `authorize` URL with `state`+`nonce`+PKCE. Reads target URL from `?rd=` query or `X-Forwarded-Uri` header. Hit by the browser after a `401` from `/oauth2/auth`. |
| **Callback** | `config.callbackURL` | GET | IdP `code`+`state` exchange. Existing `auth_flow.go` logic runs unchanged. On success → `302` to original URL. |
| **Logout** | `config.logoutURL` | GET/POST | Existing `logout.go` handler. Terminates session. Honors `oidcEndSessionURL` if configured. |

### Wiring (how each endpoint delegates)

All four handlers feed `(*TraefikOidc).ServeHTTP` after rewriting `req.URL.Path`:

- `/oauth2/callback` → rewrite to `config.callbackURL`, delegate. Middleware path-match at `middleware.go` triggers callback flow.
- `/oauth2/logout` → rewrite to `config.logoutURL`, delegate. Middleware logout path-match at the top of `ServeHTTP` triggers.
- `/oauth2/start` → rewrite `req.URL.Path` to the sentinel `/__oidcgate_protected__`, delegate. Middleware sees an unauthenticated GET on a protected path, emits the `302` to IdP. The redirect flows through naturally.
- `/oauth2/auth` → rewrite `req.URL.Path` to `/__oidcgate_protected__`, wrap `ResponseWriter` with an interceptor (see below), delegate.

The sentinel path `/__oidcgate_protected__` is chosen because it cannot collide with `callbackURL` / `logoutURL` / `/health*` path matches inside `ServeHTTP` and is not a likely user-configured `excludedURLs` entry. It is internal-only: clients never see it.

### Synthetic `next` handler

The middleware calls `t.next.ServeHTTP(rw, req)` at four sites (`middleware.go:174,185,187,592`) when the request is authenticated and should be forwarded. The daemon supplies a `next` that:

1. Writes `200 OK`.
2. Mirrors any `X-Forwarded-*` and templated headers that the middleware set on `req.Header` (e.g. `X-Forwarded-User` at `middleware.go:101,512`) onto the **response** headers, so proxies can capture them via `auth_request_set` / `authResponseHeaders`.
3. Writes empty body.

### 302 → 401 interceptor (`/oauth2/auth` only)

nginx `auth_request` cannot follow `302`s. For the silent endpoint, the daemon wraps the `ResponseWriter` such that:

- If the middleware writes status `302` (the IdP-redirect branch), the interceptor rewrites it to `401`.
- `Location` header from the swallowed `302` is preserved as `X-Auth-Redirect` on the `401` response (advisory; some proxies may surface it).
- `Set-Cookie` headers (state, PKCE, nonce) are preserved verbatim so the browser carries them into the subsequent `/oauth2/start` request.
- For any non-`302` status, the interceptor is a passthrough.

`/oauth2/start` does **not** wrap; the middleware's natural `302` flows through to the browser.

## Configuration

### Source

- **File:** `--config /etc/oidcgate/config.yaml` (path overridable via flag).
- **Format:** YAML, unmarshalled into the existing `traefikoidc.Config` struct (`settings.go:39`) via `yaml.v3` (already a dependency in `go.mod`).
- **Migration from Traefik:** copy the `plugin.traefikoidc:` subtree out of `.traefik.yml` and add the daemon-specific top-level keys below.
- **Env-var overrides** (secrets in particular): after YAML unmarshal, walk the config struct. Any scalar string/int/bool field with a non-empty `OIDCGATE_<UPPER_SNAKE_CASE_FIELD>` env-var replaces the YAML value. Nested structs (`Redis`, `SecurityHeaders`, `DynamicClientRegistration`) stay YAML-only.

### Top-level oidcgate-specific keys

```yaml
listen: ":8080"            # required, listener address
authPath: "/oauth2/auth"   # optional, default shown
startPath: "/oauth2/start" # optional, default shown
# all other keys = existing traefikoidc.Config fields
```

### Validation

The existing validation inside `traefikoidc.NewWithContext` (`main.go:97`) runs unchanged. On any returned error, the daemon logs the error and exits non-zero.

## Library-Side Patches

Two additive changes, both default-off / read-only:

1. **`settings.go` + `middleware.go` (~10 LoC):** add `Config.TrustForwardedURI bool` (default `false`). When `true`, the post-login-redirect target captured during the "unauthenticated GET → 302 to IdP" branch is sourced from `req.Header.Get("X-Forwarded-Uri")` if non-empty, instead of from `req.URL`. The daemon sets `TrustForwardedURI = true` at config build time. Default-off preserves current Traefik plugin behavior exactly.

2. **`main.go` (~5 LoC):** add `func (t *TraefikOidc) Ready() bool` returning `true` once at least one successful OIDC metadata discovery fetch has populated the metadata cache. Read-only; no behavior change for existing consumers.

## Lifecycle

```
parse flags
  → load YAML
  → apply env-var overrides
  → build synthetic success handler
  → call traefikoidc.New(ctx, success, cfg, "oidcgate")  (validation happens here)
  → build mux (auth, start, callback, logout, healthz, readyz)
  → http.Server.ListenAndServe on cfg.listen
  → wait for SIGINT/SIGTERM
  → srv.Shutdown(15s ctx)
  → ctx cancel propagates to goroutine manager
  → exit 0
```

`/readyz` returns `200` only once `traefikoidc.New` has returned without error **and** the first OIDC metadata discovery fetch has succeeded. Implementation: add a read-only accessor `func (t *TraefikOidc) Ready() bool` that returns `true` once the metadata cache has at least one successful discovery fetch. The daemon's `/readyz` handler calls this and returns `200` / `503` accordingly.

`/healthz` returns `200` as long as the process is alive.

## Testing

- `config_test.go` — YAML round-trip; env-var override precedence; validation pass-through.
- `endpoints_test.go` — `httptest.NewServer`-based scenarios:
  - `/oauth2/auth` with no session → `401`.
  - `/oauth2/auth` with valid session → `200` + `X-Forwarded-User` mirrored on response.
  - `/oauth2/start` → `302` with valid IdP `authorize` URL incl. `state` and PKCE.
  - `/oauth2/callback` → completes exchange, sets session, redirects to original URL.
  - `/oauth2/logout` → clears session cookie.
- `interceptor_test.go` — middleware-emitted `302` becomes `401`; `Location` → `X-Auth-Redirect`; `Set-Cookie` preserved.
- Reuse existing mock IdP from `enhanced_mocks_test.go`. No new mock infra.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Interceptor swallows a legitimate `302` from the middleware that isn't the IdP redirect. | Inspect: only intercept when `Location` matches `t.providerURL`'s authorize endpoint or when it points off-host. Test coverage in `interceptor_test.go`. |
| Library-side patch breaks current Traefik users. | New `TrustForwardedURI` defaults to `false`; existing path untouched when unset. |
| Env-var walker overreaches into nested structs. | Restrict to top-level scalar fields; document explicitly; nested structs stay YAML-only. |
| Path-rewrite trick hits a middleware path-comparison we didn't anticipate. | All four `t.next.ServeHTTP` sites verified at `middleware.go:174,185,187,592`. Endpoint tests exercise each path. |

## Out of Scope (Tier 2 candidates)

- Reverse-proxy mode (`httputil.ReverseProxy` as the configured `next`).
- TLS termination (`tls.Config`, ACME).
- Prometheus metrics endpoint.
- Multi-tenant routing.
- oauth2-proxy flag/env compatibility.
- Goreleaser binaries, Docker image, systemd unit.

## Acceptance Criteria

1. `go build ./cmd/oidcgate` produces a working binary.
2. Existing test suite (`go test ./...`) still passes — zero regressions in the library.
3. New endpoint tests pass for all four endpoints against the mock IdP.
4. `oidcgate --config example.yaml` boots, serves `/healthz`, performs end-to-end OIDC flow against a real IdP (manual smoke test against e.g. a local Keycloak).
5. README section documents nginx, Caddy, and Traefik wiring examples.
