# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **`allowUnauthenticatedPreflight` (default `false`).** Every `OPTIONS`
  request needs authentication by default, as in the last release. Set the
  option to `true` to let a genuine CORS preflight reach the backend
  without a session. Only an `OPTIONS` request that carries both `Origin`
  and `Access-Control-Request-Method` bypasses authentication, and the
  plugin discards the backend's response body for it, because a browser
  never reads a preflight body (`settings.go`, `middleware.go`, FIX-02).
  See the option table in [CONFIGURATION.md](docs/CONFIGURATION.md).

### Changed

- **Opaque bearer tokens when all three bearer flags are set.** A deployment
  that sets `enableBearerAuth`, `requireTokenIntrospection` and
  `allowOpaqueTokens` now accepts opaque bearer tokens after RFC 7662
  introspection. The last release rejected every non-JWT bearer token. The
  plugin binds an accepted opaque token to the client through `client_id` or
  `aud`. It also applies the identifier, token-age, logout, revocation and
  `nbf` checks (`bearer_auth.go`).

- **Sessions created before this upgrade can omit `post_logout_redirect_uri`
  on their first logout.** The plugin now builds that parameter only from the
  redirect-URI origin recorded at login, never from the logout request's
  host. Older sessions have no recorded origin, so those users stay on the
  IdP's logout page once (`helpers.go`).

- **Shutdown waits up to 5 seconds for a token refresh in progress.** On
  shutdown, for example a Traefik reload, the refresh coordinator lets a
  refresh that already reached the IdP deliver its tokens, then returns
  (`shutdownRefreshDrainTimeout`, `refresh_coordinator.go`). A refresh that
  has not started does not start after shutdown.

- **A panic after the request reaches the backend now aborts the
  connection.** The plugin re-panics it, for example the reverse proxy's
  `http.ErrAbortHandler` when an upstream drops the connection mid-body. Go's
  HTTP server then aborts the connection. Before, the plugin recovered the
  panic, so a truncated response could reach the client as a complete 200. A
  panic before the request reaches the backend still returns 500
  (`middleware.go`).

- **private_key_jwt now rejects RSA signing keys under 2048 bits.**
  `validateAlgKeyMatch` stops `New()` with an error when a configured
  `private_key_jwt` RS\*/PS\* key is smaller than 2048 bits (RFC 7518 §3.3).
  A smaller key signs locally, but a conformant IdP rejects it at token
  exchange with `invalid_client`, so the plugin now fails at construction
  instead of at every runtime exchange. There is no override: deployments
  using an RSA key under 2048 bits must generate a 2048-bit-or-larger key
  before upgrading. The rejection returns a matchable `ErrRSAKeyTooSmall`
  sentinel (`client_assertion.go`).

- **A discovered `http://` endpoint is now dropped when `providerURL` is
  `https://`.** `validateDiscoveredEndpoint` refuses to accept an
  authorization, token, jwks_uri, revocation, end_session, introspection, or
  registration endpoint served over plaintext HTTP when the operator
  configured an HTTPS provider (R146): using it as-is would send a client
  secret or token over an unauthenticated channel. There is no configuration
  flag to disable this check. A dropped endpoint logs an `ERROR` line; a
  dropped `token`, `jwks_uri`, or `authorization` endpoint — the three
  every login needs — additionally logs a `SECURITY:`-prefixed line naming
  the endpoint, the dropped URL, and the fact that there is no override, so
  the failure is diagnosable instead of surfacing only as a broken login.
  See [Discovered Endpoint
  Validation](docs/CONFIGURATION.md#discovered-endpoint-validation)
  (`url_helpers.go`, `main.go`).

- **Blacklist entries in Redis use the `blacklist:` key prefix.** The
  blacklist cache now has its own cache type (`CacheTypeBlacklist`), so its
  Redis keys move from the shared `token:` prefix to `blacklist:` (R128).
  A cached token entry and a revocation marker for the same raw token can
  no longer overwrite each other. For one release, a blacklist miss also
  reads the legacy `token:<key>` entry and treats it as revoked only when
  the stored value is boolean `true` (`checkLegacyBlacklistMarker` in
  `universal_cache.go`, FIX-16). The fallback works in one direction only:
  during a rolling deploy, a replica that runs the previous version does
  not see revocations that an upgraded replica writes under `blacklist:`.
  A blacklist miss checks the legacy `token:` entry at most once per key in
  each 30 seconds, so the fallback adds little Redis traffic.

- **Claim validation accepts four previously-rejected or silently-dropped
  claim shapes.** Each change below is intentional, matches a production
  change, and is pinned by an existing regression test.
  - `iat` (issued-at) is optional in `jwt.Verify`, per RFC 7519 §4.1.6. A
    token that omits it is validated on `iss`/`aud`/`exp`/`nbf` alone,
    instead of being rejected (`jwt.go`, R126). The lenient-audience
    access-token path (`accessTokenUnexpired` in `token_validation_rs.go`)
    applies the same rule, because both paths call `verifyTimeClaims`
    (`jwt.go`, FIX-27). Bearer-token auth still rejects a token with no
    `iat`: it returns `"missing iat claim"` (`enforceIatAge` in
    `bearer_auth.go`), because `maxTokenAgeSeconds` always applies — `0`
    falls back to a 24h default (`main.go`).
  - A numeric `sub` (bearer-auth identifier) claim is stringified instead of
    rejected, so an IdP that emits a numeric subject still authenticates
    (`bearer_auth.go` `resolveBearerIdentifier`, R102).
  - A `groups`/`roles` claim that is neither a string nor an array (for
    example a bare number or `null`) is treated as an empty list instead of
    failing claim extraction outright, so a malformed claim on one side does
    not suppress a valid claim on the other (`token_manager.go`
    `extractGroupsAndRolesFromClaims`, R96).
  - A numeric element inside a `groups`/`roles` array is stringified into
    the list instead of being silently dropped, so a numeric group ID
    survives extraction and can match an `allowedRolesAndGroups` entry
    (`token_manager.go` `stringListFromClaim`, `utilities.go`
    `claimScalarString`, R105).

### Fixed

- The opaque bearer path rejects a token that `RevokeToken` added to the
  blacklist, for example at logout. It also rejects an opaque token whose
  `nbf` is in the future (`bearer_auth.go`).
- The backchannel-logout replay check treats a Redis error reply such as
  `READONLY`, `OOM` or `MISCONF` as a failure, not as an unknown outcome. A
  replayed logout token is now rejected while Redis refuses writes
  (`internal/cache/backends/redis.go`).
- After a failed cache write, a replica no longer ignores a newer value that
  another replica wrote, such as a later logout. The preference for the local
  value expires after 5 seconds (`backendStaleMarkTTL`, `universal_cache.go`).
- The token circuit breaker treats HTTP 408 from the token endpoint as a
  transient failure, the same as 429 (`error_recovery.go`).
- With `allowUnauthenticatedPreflight` enabled, a preflight response no longer
  carries a stale `Content-Length` when the backend writes a body without
  calling `WriteHeader` (`middleware.go`).
- A dropped `http://` revocation, end-session or introspection endpoint logs
  the `SECURITY:` line when its override (`revocationURL`, `oidcEndSessionURL`
  or `introspectionURL`) is not configured (`main.go`).
