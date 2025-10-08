# Auth0 Audience Validation Guide

## Overview

This guide explains how to configure audience validation for Auth0 and other OIDC providers that support custom API audiences. It covers three common Auth0 scenarios and how to configure the middleware for maximum security.

## Table of Contents

1. [Understanding Audiences](#understanding-audiences)
2. [The Three Auth0 Scenarios](#the-three-auth0-scenarios)
3. [Configuration Options](#configuration-options)
4. [Security Recommendations](#security-recommendations)
5. [Troubleshooting](#troubleshooting)

---

## Understanding Audiences

### What is an Audience?

The **audience** (`aud`) claim in a JWT identifies the intended recipient of the token. Per OAuth 2.0 and OIDC specifications:

- **ID Tokens**: MUST have `aud = client_id` (per OIDC Core 1.0 spec)
- **Access Tokens**: Can have custom audiences (e.g., API identifiers)

### Why Does This Matter?

Proper audience validation prevents **token confusion attacks** where a token intended for one API is used to access another API.

---

## The Three Auth0 Scenarios

### Scenario 1: Custom API Audience ✅ **RECOMMENDED**

**Configuration:**
```yaml
audience: "https://my-api.example.com"  # Your API identifier from Auth0
```

**What Happens:**
1. Authorization request includes `audience` parameter
2. Auth0 issues:
   - **ID Token**: `aud = client_id`
   - **Access Token**: `aud = ["https://issuer/userinfo", "https://my-api.example.com"]`
3. Middleware validates:
   - ID tokens against `client_id`
   - Access tokens against custom audience

**Result:** ✅ Fully secure, OIDC compliant

---

### Scenario 2: Default Audience (No Custom API) ⚠️ **USE WITH CAUTION**

**Configuration:**
```yaml
# audience not specified (defaults to client_id)
```

**What Happens:**
1. Authorization request WITHOUT `audience` parameter
2. Auth0 issues:
   - **ID Token**: `aud = client_id`
   - **Access Token**: `aud = ["https://issuer/userinfo", "default_api"]` (no `client_id`)
3. Access token validation fails (audience mismatch)
4. Middleware falls back to ID token validation

**Security Warning:**
```
⚠️⚠️⚠️  SECURITY WARNING: Falling back to ID token validation despite access token audience mismatch!
⚠️  This could allow tokens intended for different APIs to grant access
⚠️  Set strictAudienceValidation=true to enforce proper audience validation
⚠️  See: https://github.com/lukaszraczylo/traefikoidc/issues/74
```

**Recommended Fix:**
```yaml
strictAudienceValidation: true  # Reject sessions with audience mismatch
```

**Result:**
- Default: ⚠️ Works but logs security warnings
- With strict mode: ✅ Secure (rejects mismatched tokens)

---

### Scenario 3: Opaque Access Tokens ✅ **SUPPORTED**

**Configuration:**
```yaml
allowOpaqueTokens: true              # Enable opaque token support
requireTokenIntrospection: true      # Require introspection (recommended)
```

**What Happens:**
1. Auth0 issues opaque (non-JWT) access token
2. Middleware detects opaque token (not 3 parts separated by dots)
3. Uses OAuth 2.0 Token Introspection (RFC 7662) to validate
4. Falls back to ID token if introspection unavailable (unless `requireTokenIntrospection=true`)

**Requirements:**
- Provider must support `introspection_endpoint` in OIDC discovery
- Client must have introspection permissions

**Result:** ✅ Secure with introspection, ⚠️ risky without

---

## Configuration Options

### Audience Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `audience` | string | `client_id` | Expected audience for access tokens |

**Example:**
```yaml
# .traefik.yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefikoidc:
          audience: "https://my-api.example.com"
```

---

### Security Mode Settings

#### `strictAudienceValidation`

**Type:** boolean
**Default:** `false`
**Recommended:** `true` for production

**What it does:**
- When `true`: Rejects sessions if access token audience doesn't match (prevents Scenario 2)
- When `false`: Logs warnings but allows fallback to ID token (backward compatible)

**Example:**
```yaml
strictAudienceValidation: true
```

**When to use:**
- ✅ Always use in production environments
- ✅ When you have custom API audiences configured in Auth0
- ⚠️ May break existing deployments relying on Scenario 2 behavior

---

#### `allowOpaqueTokens`

**Type:** boolean
**Default:** `false`

**What it does:**
- When `true`: Accepts opaque (non-JWT) access tokens
- When `false`: Only accepts JWT access tokens

**Example:**
```yaml
allowOpaqueTokens: true
```

**When to use:**
- ✅ When Auth0 issues opaque tokens (no default API configured)
- ✅ When using Auth0 Management API tokens
- ⚠️ Requires introspection endpoint for security

---

#### `requireTokenIntrospection`

**Type:** boolean
**Default:** `false`
**Recommended:** `true` when `allowOpaqueTokens=true`

**What it does:**
- When `true`: Rejects opaque tokens if introspection fails or endpoint unavailable
- When `false`: Falls back to ID token validation for opaque tokens

**Example:**
```yaml
allowOpaqueTokens: true
requireTokenIntrospection: true
```

**When to use:**
- ✅ Always use when `allowOpaqueTokens=true` for maximum security
- ⚠️ Requires provider to expose introspection endpoint

---

## Security Recommendations

### Recommended Configuration for Auth0

**For APIs with custom audiences (Scenario 1):**
```yaml
audience: "https://my-api.example.com"
strictAudienceValidation: true
allowOpaqueTokens: false
```

**For default Auth0 setup (Scenario 2):**
```yaml
# Don't set audience (defaults to client_id)
strictAudienceValidation: true  # Enforce proper configuration
```

**For opaque tokens (Scenario 3):**
```yaml
allowOpaqueTokens: true
requireTokenIntrospection: true
strictAudienceValidation: true
```

### Security Best Practices

1. ✅ **Always set `strictAudienceValidation: true` in production**
2. ✅ **Configure custom API audiences in Auth0 dashboard**
3. ✅ **Use `requireTokenIntrospection: true` if accepting opaque tokens**
4. ✅ **Monitor logs for security warnings**
5. ❌ **Don't rely on Scenario 2 fallback behavior**

---

## Troubleshooting

### "Access token validation failed due to audience mismatch"

**Symptom:**
```
⚠️  SCENARIO 2 DETECTED: Access token validation failed due to audience mismatch
```

**Cause:** Access token audience doesn't match configured audience

**Solutions:**
1. **Configure correct audience:**
   ```yaml
   audience: "https://your-api-identifier"  # From Auth0 API settings
   ```

2. **Update Auth0 authorization request:**
   - Ensure `audience` parameter is included in authorize URL
   - Middleware automatically adds this when `audience != client_id`

3. **Accept the behavior (not recommended):**
   ```yaml
   strictAudienceValidation: false  # Logs warnings but allows
   ```

---

### "Opaque token detected but allowOpaqueTokens=false"

**Symptom:**
```
⚠️  Opaque access token detected but allowOpaqueTokens=false
```

**Cause:** Auth0 issued non-JWT access token but middleware not configured to accept them

**Solutions:**
1. **Enable opaque tokens:**
   ```yaml
   allowOpaqueTokens: true
   requireTokenIntrospection: true
   ```

2. **Configure Auth0 to issue JWT access tokens:**
   - Create an API in Auth0 dashboard
   - Set API identifier as `audience` in configuration

---

### "Introspection endpoint not available"

**Symptom:**
```
⚠️  Opaque tokens enabled but no introspection endpoint available from provider
```

**Cause:** Auth0 provider metadata doesn't include `introspection_endpoint`

**Solutions:**
1. **Check provider discovery:**
   ```bash
   curl https://YOUR_DOMAIN/.well-known/openid-configuration
   ```
   Look for `introspection_endpoint`

2. **Disable required introspection (less secure):**
   ```yaml
   allowOpaqueTokens: true
   requireTokenIntrospection: false  # Falls back to ID token
   ```

3. **Use JWT access tokens instead** (recommended)

---

### "Token introspection required but endpoint not available"

**Symptom:**
```
❌ SECURITY: Opaque token rejected (introspection required but failed)
```

**Cause:** `requireTokenIntrospection=true` but provider doesn't support it

**Solutions:**
1. **Disable required introspection:**
   ```yaml
   requireTokenIntrospection: false
   ```

2. **Configure Auth0 to issue JWT tokens** (better solution)

---

## Advanced Topics

### Token Type Detection

The middleware uses a sophisticated 6-step detection algorithm:

1. **RFC 9068 `typ` header**: `at+jwt` → Access Token
2. **Explicit type claims**: `token_use`, `token_type`
3. **`scope` claim**: Present → Access Token
4. **`nonce` claim**: Present → ID Token (OIDC spec)
5. **Audience check**: `aud == client_id` only → ID Token
6. **Default**: Access Token

### OAuth 2.0 Token Introspection (RFC 7662)

When opaque tokens are detected:

1. Middleware calls provider's `introspection_endpoint`
2. Authenticates using client credentials
3. Receives response with `active` status and claims
4. Caches result for 5 minutes (configurable via TTL)
5. Validates expiration, not-before, and audience if present

**Cache behavior:**
- Cache key: Token hash
- TTL: 5 minutes or token expiry (whichever is shorter)
- Reduces introspection requests for frequently used tokens

---

## Reference Links

- [GitHub Issue #74](https://github.com/lukaszraczylo/traefikoidc/issues/74) - Original Auth0 audience discussion
- [OIDC Core 1.0 Spec](https://openid.net/specs/openid-connect-core-1_0.html) - ID Token requirements
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) - OAuth 2.0 specification
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) - OAuth 2.0 Token Introspection
- [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) - JWT Access Token Profile
- [Auth0 API Authorization](https://auth0.com/docs/secure/tokens/access-tokens) - Auth0 audience documentation

---

## Migration Guide

### From Previous Versions

**If you're upgrading from a version without these features:**

1. **No action required for default behavior** - backward compatible
2. **Recommended: Enable strict mode gradually**
   ```yaml
   # Step 1: Enable and monitor logs
   strictAudienceValidation: false  # Default

   # Step 2: After confirming no warnings, enable
   strictAudienceValidation: true
   ```

3. **For opaque tokens: Enable explicitly**
   ```yaml
   allowOpaqueTokens: true
   requireTokenIntrospection: true
   ```

### Testing Your Configuration

1. **Check logs for warnings:**
   ```bash
   # Look for Scenario 2 warnings
   grep "SCENARIO 2 DETECTED" /var/log/traefik.log

   # Look for opaque token warnings
   grep "Opaque" /var/log/traefik.log
   ```

2. **Test with curl:**
   ```bash
   # Get token from Auth0
   ACCESS_TOKEN="your_access_token"

   # Test request
   curl -H "Authorization: Bearer $ACCESS_TOKEN" \
        https://your-app.example.com/api
   ```

3. **Monitor for security warnings in production logs**

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/lukaszraczylo/traefikoidc/issues
- Security issues: See SECURITY.md for responsible disclosure

---

**Last Updated:** 2025-01-09
**Version:** 0.7.8+
