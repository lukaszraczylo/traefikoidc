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
