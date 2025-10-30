# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2025-10-30

### ⚠️ BREAKING CHANGES

**Session Cookie Names Changed**

All users will be logged out and need to re-authenticate after upgrading to v0.8.0.

**Why:** Cookie names are now namespaced by middleware instance to support multiple Keycloak realms on the same domain. This fixes critical bugs that prevented multi-realm deployments from working correctly.

**Before:** `_oidc_raczylo_m`
**After:** `_oidc_raczylo_m_{instance-name}`

**Migration:** See [MIGRATION-0.8.0.md](MIGRATION-0.8.0.md) for detailed upgrade instructions.

### 🔧 Fixed

#### Critical: Multi-Realm Support Restored

Fixed critical bugs preventing multiple Keycloak realms/OIDC providers from working on the same domain:

1. **Metadata Refresh Task Collision** ([#1](https://github.com/lukaszraczylo/traefikoidc/issues/XXX))
   - Each middleware instance now has a unique metadata refresh task based on its instance name
   - Previously: All instances shared one task, causing only the first realm to refresh metadata
   - Now: Each realm independently refreshes its metadata every 2 hours
   - Files: `main.go:399-436`

2. **Session Cookie Collision** ([#2](https://github.com/lukaszraczylo/traefikoidc/issues/XXX))
   - Session cookies are now namespaced by middleware instance identifier
   - Previously: All instances used the same cookie names, causing session data to overwrite between realms
   - Now: Each realm has isolated session cookies
   - Files: `session.go:258-294`, `main.go:223`

3. **Instance Name Collision Vulnerability**
   - Long instance names now use hashing to guarantee uniqueness
   - Previously: Names longer than 32 chars were truncated, causing collisions for similar names
   - Now: Names >20 chars use format `first_12_chars_hash` (e.g., `my_super_lon_7cc4ac39`)
   - Test: `session_test.go:1772-1840`
   - Files: `session.go:258-294`

### ✨ Added

- **Multi-Realm Support**
  - Multiple Keycloak realms or OIDC providers can now coexist on the same domain
  - Each middleware instance maintains independent:
    - Metadata refresh tasks
    - Session cookies
    - Token caches
    - Background tasks
  - See [MIGRATION-0.8.0.md](MIGRATION-0.8.0.md) for configuration examples

- **Hash-Based Instance Name Sanitization**
  - Prevents cookie name collisions for long instance names
  - Uses FNV-1a 32-bit hashing for uniqueness guarantee
  - Cookie names stay under 50 characters for browser compatibility
  - Files: `session.go:258-294`

- **URLValidator Interface**
  - New interface for URL validation with dependency injection
  - `ProductionURLValidator`: Strict SSRF protection (default)
  - `PermissiveURLValidator`: Test-only helper (test files only)
  - Enables testing with localhost without compromising production security
  - Files: `url_helpers.go:14-92`

### 🧪 Tests

- Added `TestSessionCookieNameUniquenessWithLongNames` - Verifies hash-based collision prevention
- Updated `TestMultipleRealms*` - All multi-realm tests now use dependency injection
- All tests pass with `-race` flag enabled

### 📚 Documentation

- Added `MIGRATION-0.8.0.md` - Comprehensive upgrade guide
- Added `CHANGELOG.md` - This file
- Updated inline documentation for URLValidator interface

---

## [0.7.10] - 2025-10-29

Previous stable release. See git history for details.

---

## Migration Notes

### From v0.7.x to v0.8.0

**⚠️ All users must re-authenticate after upgrade.**

See [MIGRATION-0.8.0.md](MIGRATION-0.8.0.md) for:
- Detailed breaking changes explanation
- Step-by-step upgrade procedure
- Testing checklist
- Rollback instructions
- FAQ

**Recommended for:**
- ✅ All users (especially multi-realm deployments)
- ✅ Anyone experiencing "authentication works for first realm only" issues
- ✅ Security-conscious deployments (removes test bypass)

**Timeline estimate:** 5-15 minutes for single-realm, 15-30 minutes for multi-realm

---

## Support

- **Issues:** https://github.com/lukaszraczylo/traefikoidc/issues
- **Documentation:** https://github.com/lukaszraczylo/traefikoidc
- **Migration Guide:** [MIGRATION-0.8.0.md](MIGRATION-0.8.0.md)

---

[0.8.0]: https://github.com/lukaszraczylo/traefikoidc/compare/v0.7.10...v0.8.0
[0.7.10]: https://github.com/lukaszraczylo/traefikoidc/releases/tag/v0.7.10
