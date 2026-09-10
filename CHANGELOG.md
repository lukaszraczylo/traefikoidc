# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

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
