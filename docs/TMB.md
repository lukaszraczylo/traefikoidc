# Token-mediating backend endpoint

Lets a single-page app obtain an access token from the plugin's session without
holding a refresh token or running its own OAuth client. This is the
"Token-Mediating Backend" pattern of
[draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps):
the plugin is the confidential client, keeps the refresh token server-side, and
hands the access token to the browser. It is not a BFF: requests to the
resource server do not pass through the plugin.

The spec defines no paths or formats. The endpoint is modelled on session
endpoints such as Azure App Service's `/.auth/me`: `GET` reads, `POST`
refreshes.

## Configuration

The endpoint is off until its path is set. There is no separate enable flag.

```yaml
tmbSessionURL: /auth/session
tmbClaims:        # optional; default none
  - email
  - name
```

The path must be a plain absolute path (leading `/`, no leading `//`, no query,
fragment or backslash) and must not be a path another endpoint of the
middleware already serves: `callbackURL`, `logoutURL` (its default is
`callbackURL` + `/logout`) or the back- and front-channel logout URLs. It is
matched against the request path as configured.

`tmbClaims` names the claims returned in `claims`, read from the ID token (from
the access token when the session has no ID token). It is empty by default, so
nothing beyond the fields below is exposed.

## Authentication

The endpoint is authenticated by the plugin's session cookie, the same one the
rest of the plugin uses. It never accepts `Authorization: Bearer` and never
redirects to the IdP: with no valid session it answers `401 invalid_session`. It
is served ahead of the bypasses (`excludedURLs`, `Accept: text/event-stream`,
WebSocket upgrades, unauthenticated preflight), so none of them can forward a
request on its path to the backend.

A session must also pass the normal gates (`allowedUsers`, `allowedUserDomains`,
`allowedRolesAndGroups`, back/front-channel logout invalidation); failing
`allowedUsers`/`allowedRolesAndGroups` answers `403 access_denied`.

If `cookiePath` is set, it must cover the configured path, or the browser will
not send the cookie to it.

## Cross-origin protection

- `GET` and `POST` only (`405` otherwise, with `Allow: GET, POST`).
- A request is rejected with `403` when `Sec-Fetch-Site` is `cross-site` or
  `same-site`, or when `Origin` is present and does not match the request host.
  A rejected request never triggers a refresh.
- The endpoint never emits CORS headers: `Access-Control-*` headers added by
  `securityHeaders.corsEnabled` are removed from its responses.
- Responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
  and `Cross-Origin-Resource-Policy: same-origin`.
- No custom request header is required.

## `GET`: read the session

```json
{
  "authenticated": true,
  "user_identifier": "user-1",
  "claims": {"email": "u@example.com", "name": "U One"},
  "groups": ["admins"],
  "expires_at": 1767225600,
  "access_token": "…",
  "expires_in": 3540
}
```

- `user_identifier` is the claim named by `userIdentifierClaim`. `groups` and
  `roles` use `groupClaimName` / `roleClaimName` and are omitted when empty.
  `expires_at` is the `exp` of the ID token, or of the access token when the
  session has no ID token (providers that issue none).
- `claims` holds exactly the claims listed in `tmbClaims`, with their values as
  they appear in the token (arrays and objects included). A claim the token
  lacks is omitted, and `claims` itself is omitted when nothing is listed.
- `access_token` is the session's access token. `expires_in` is derived from
  its `exp` claim and omitted for opaque tokens. The refresh token and ID token
  are never returned.
- A `GET` has no side effects on the session, except that a token within
  `refreshGracePeriod` of expiry is refreshed first, as for any other request.
  Query parameters are ignored.

## `POST`: force a refresh

Runs a refresh-token grant through the same path as the automatic refresh,
saves the new tokens and any rotated refresh token to the session, and returns
the same body as `GET` with the new token. Use it when the API rejected the
current token. The request body is ignored. The refresh runs only after the
user passed the authorization gates, which are applied again to the refreshed
token's claims. Each forced refresh is one IdP call, so it is subject to
`perSourceLoginRateLimit` when that is set (off by default).

## Errors

`application/json` with `error` and optional `error_description`:

| Status | `error` | Cause |
|--------|---------|-------|
| 401 | `invalid_session` | No valid authenticated session (missing, expired or logged out), or the IdP rejected the refresh token on `POST` (the session is ended). No `WWW-Authenticate` header is sent: the session cookie has no HTTP auth scheme, as for the plugin's other `401`s. |
| 401 | `backend_not_ready` | `POST` but the session has no refresh token, so it cannot be refreshed and the user has to authenticate again. The session is left as is; `GET` keeps working until the access token expires. |
| 403 | `access_denied` | The user fails `allowedUsers` or `allowedRolesAndGroups`. |
| 403 | `invalid_request` | Cross-origin request. |
| 405 | `invalid_request` | Method other than `GET` or `POST`. |
| 429 | `rate_limited` | `POST` from an external source over `perSourceLoginRateLimit`; `Retry-After: 1` is set and no refresh is attempted. |
| 502 | `server_error` | `POST` and the token endpoint was unreachable or failed; the session is kept. |

## SPA flow

Read the session once on load and keep the access token in memory. When the API
answers `401` or `expires_in` runs out, `POST` to get a fresh one. The endpoint
never redirects: on any `401` from this endpoint (`invalid_session` or
`backend_not_ready`), navigate the page to a protected URL so the normal login
redirect runs. No page reload is needed otherwise.

## Not supported

`resource` and `scope` (token downscoping) are not supported in this version.
