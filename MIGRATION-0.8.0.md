# Migration Guide: v0.7.x → v0.8.0

## ⚠️ Breaking Changes Overview

**Version 0.8.0** introduces critical bug fixes for multi-realm support that require changes to session cookie naming. **All users will be logged out and need to re-authenticate after upgrading.**

### Summary of Changes

1. **Session Cookie Names Changed** - Cookie names now include middleware instance identifier
2. **Security Enhancement** - Removed test-only security bypass from production code
3. **Collision Prevention** - Instance names now use hashing to prevent cookie collisions
4. **Error Handling** - SessionManager creation errors now properly handled

---

## Breaking Change: Session Cookie Names

### Impact

**All authenticated users will be logged out after the upgrade and must re-authenticate.**

This is a one-time inconvenience required to fix critical multi-realm bugs.

### Why This Changed

Cookie names are now namespaced by middleware instance to support multiple Keycloak realms on the same domain. Previously, all middleware instances used the same cookie names, causing session data to collide and overwrite each other.

### Cookie Name Format

**Before (v0.7.x):**
```
_oidc_raczylo_m      (main session)
_oidc_raczylo_a      (access token)
_oidc_raczylo_r      (refresh token)
_oidc_raczylo_id     (ID token)
```

**After (v0.8.0):**
```
_oidc_raczylo_m_{instance-id}      (main session)
_oidc_raczylo_a_{instance-id}      (access token)
_oidc_raczylo_r_{instance-id}      (refresh token)
_oidc_raczylo_id_{instance-id}     (ID token)
```

**Example with instance name "realm-a-middleware":**
```
_oidc_raczylo_m_realm_a_middleware
_oidc_raczylo_a_realm_a_middleware
_oidc_raczylo_r_realm_a_middleware
_oidc_raczylo_id_realm_a_middleware
```

**Example with long instance name (hashed for uniqueness):**
```
Instance: "my-super-long-keycloak-realm-name-for-environment-staging-us-east-1"
Cookies:  _oidc_raczylo_m_my_super_lon_7cc4ac39
```

---

## Recommended Upgrade Process

### 1. Test in Staging Environment

Before upgrading production, test in a staging environment:

```bash
# Deploy v0.8.0 to staging
# Verify authentication works
# Test multi-realm scenarios if applicable
# Check that sessions persist correctly
```

### 2. Notify Users

**Sample notification:**
```
Subject: Maintenance Window - Authentication System Upgrade

Dear Users,

We will be upgrading our authentication system on [DATE] at [TIME].

What to expect:
- You will be logged out automatically
- You will need to log in again after the upgrade
- Your data and preferences will not be affected
- The upgrade should take less than 5 minutes

Thank you for your patience.
```

### 3. Schedule During Low Traffic

Choose a maintenance window with minimal user impact:
- Off-peak hours
- Weekend if applicable
- Consider time zones for global users

### 4. Upgrade Steps

```bash
# 1. Backup current configuration
cp traefik.yml traefik.yml.backup

# 2. Update plugin version
# In your Traefik dynamic configuration:
# traefikoidc version: v0.8.0

# 3. Restart Traefik
systemctl restart traefik
# or
docker-compose restart traefik

# 4. Monitor logs for errors
tail -f /var/log/traefik/traefik.log

# 5. Verify authentication works
curl -I https://your-app.example.com/protected
# Should redirect to OIDC provider
```

### 5. Monitor After Upgrade

Watch for:
- ✅ Users can authenticate successfully
- ✅ Sessions persist across requests
- ✅ No cookie-related errors in logs
- ✅ Multiple realms work independently (if applicable)

---

## What's Fixed in v0.8.0

### Critical Bug Fixes

#### 1. Multi-Realm Metadata Refresh Collision

**Problem:** When using multiple Keycloak realms, only the first realm would refresh its metadata. Other realms would skip refresh, potentially using stale or incorrect endpoints.

**Fixed:** Each middleware instance now has a unique metadata refresh task based on its instance name.

**Before:**
```
Realm A: singleton-metadata-refresh ✅ Runs
Realm B: singleton-metadata-refresh ❌ Skipped (already running)
```

**After:**
```
Realm A: singleton-metadata-refresh-realm-a ✅ Runs
Realm B: singleton-metadata-refresh-realm-b ✅ Runs
```

#### 2. Session Cookie Collision

**Problem:** Multiple realms used the same cookie names, causing session data to overwrite each other. This led to authentication failures, wrong realm validation, and token mismatches.

**Fixed:** Cookie names now include the middleware instance identifier.

**Before:**
```
Realm A sets: _oidc_raczylo_m (contains Realm A session)
Realm B sets: _oidc_raczylo_m (OVERWRITES Realm A session) ❌
```

**After:**
```
Realm A sets: _oidc_raczylo_m_realm_a (isolated)
Realm B sets: _oidc_raczylo_m_realm_b (isolated) ✅
```

#### 3. Instance Name Collision Vulnerability

**Problem:** Long instance names were truncated to 32 characters, causing collisions for names that differed only at the end.

**Fixed:** Long names now include a hash to guarantee uniqueness.

**Before:**
```
"staging-us-east-1-production" → "staging_us_east_1_production"
"staging-us-west-2-production" → "staging_us_west_2_production" (truncated same!)
```

**After:**
```
"staging-us-east-1-production" → "staging_us__7cc4ac39" ✅
"staging-us-west-2-production" → "staging_us__7e8eab1a" ✅
```

#### 4. Security: Removed Test Bypass

**Problem:** A `AllowLocalhostRedirect` configuration flag bypassed SSRF protection, creating a security vulnerability if accidentally enabled in production.

**Fixed:** Removed the flag entirely. Tests now use dependency injection with a test-only validator that never appears in production code.

#### 5. Error Handling

**Problem:** SessionManager creation errors were ignored, potentially causing nil pointer panics on first request.

**Fixed:** Errors are now properly caught and returned with context.

---

## Multi-Realm Support (New Feature)

If you were previously unable to use multiple Keycloak realms or OIDC providers on the same domain, **v0.8.0 makes this possible!**

### Configuration Example

```yaml
# Traefik dynamic configuration
http:
  middlewares:
    # Realm A for internal employees
    realm-a-auth:
      plugin:
        traefikoidc:
          providerURL: https://keycloak.example.com/realms/employees
          clientID: employees-client
          clientSecret: secret-a
          callbackURL: /oauth2/callback
          sessionEncryptionKey: your-encryption-key-here

    # Realm B for external partners
    realm-b-auth:
      plugin:
        traefikoidc:
          providerURL: https://keycloak.example.com/realms/partners
          clientID: partners-client
          clientSecret: secret-b
          callbackURL: /oauth2/callback
          sessionEncryptionKey: your-encryption-key-here

  routers:
    # Internal app uses Realm A
    internal-app:
      rule: "Host(`internal.example.com`)"
      middlewares:
        - realm-a-auth
      service: internal-app-service

    # Partner portal uses Realm B
    partner-portal:
      rule: "Host(`partners.example.com`)"
      middlewares:
        - realm-b-auth
      service: partner-portal-service
```

### What Works Now

Each middleware instance now has:
- ✅ **Independent metadata refresh** - No collision between realms
- ✅ **Isolated session cookies** - No cross-contamination of session data
- ✅ **Separate token caches** - Each realm manages its own tokens
- ✅ **Unique background tasks** - No duplicate or conflicting tasks

---

## Testing Checklist

After upgrading to v0.8.0, verify:

### Single-Realm Deployments

- [ ] Users can authenticate successfully
- [ ] Sessions persist across page refreshes
- [ ] Sessions persist across browser restarts (if using persistent cookies)
- [ ] Logout clears all session cookies
- [ ] Token refresh works correctly before expiration
- [ ] No errors in Traefik logs related to sessions

### Multi-Realm Deployments

- [ ] Each realm authenticates independently
- [ ] Users can authenticate to Realm A without affecting Realm B
- [ ] Sessions don't conflict between realms
- [ ] Browser cookies show unique names for each realm
- [ ] Metadata refresh works for all realms
- [ ] Check logs show unique task names per realm

### Cookie Verification (Browser DevTools)

Open Browser DevTools → Application → Cookies → Check for:

**Single Realm Example:**
```
_oidc_raczylo_m_realm_a_middleware
_oidc_raczylo_a_realm_a_middleware
_oidc_raczylo_r_realm_a_middleware
_oidc_raczylo_id_realm_a_middleware
```

**Multi-Realm Example:**
```
Cookies for Realm A:
_oidc_raczylo_m_realm_a_middleware
_oidc_raczylo_a_realm_a_middleware
...

Cookies for Realm B:
_oidc_raczylo_m_realm_b_middleware
_oidc_raczylo_a_realm_b_middleware
...
```

---

## Rollback Procedure

If issues occur after upgrade:

### Option 1: Quick Rollback

```bash
# 1. Restore previous configuration
cp traefik.yml.backup traefik.yml

# 2. Set plugin version back to v0.7.10
# In dynamic config: traefikoidc version: v0.7.10

# 3. Restart Traefik
systemctl restart traefik

# 4. Notify users they need to re-authenticate AGAIN
```

**Note:** Users will need to re-authenticate again due to cookie name changes reverting.

### Option 2: Stay on v0.8.0 and Debug

```bash
# 1. Check Traefik logs
tail -f /var/log/traefik/traefik.log

# 2. Common issues and solutions:
#    - "Failed to create session manager" → Check encryption key length (min 32 bytes)
#    - "No such host" errors → Check providerURL is accessible
#    - "CSRF token mismatch" → Cookie domain settings might need adjustment

# 3. Enable debug logging temporarily
# In config: logLevel: debug

# 4. Report issues: https://github.com/lukaszraczylo/traefikoidc/issues
```

---

## Compatibility Notes

### Minimum Requirements

- Go 1.21+ (no change)
- Traefik v2.10+ or v3.0+ (no change)
- Session encryption key: minimum 32 bytes (enforced more strictly now)

### Browser Compatibility

Cookie names are now longer but still within browser limits:
- Chrome/Edge: 4096 bytes per cookie ✅
- Firefox: 4096 bytes per cookie ✅
- Safari: 4096 bytes per cookie ✅

Maximum cookie name length in v0.8.0: ~46 characters (well within limits)

### Load Balancer / Proxy Considerations

If using multiple Traefik replicas:
- ✅ Session cookies work across replicas (same encryption key)
- ✅ Metadata cache is shared via singleton pattern
- ✅ JWK cache is shared via singleton pattern

---

## Frequently Asked Questions

### Q: Why do all users need to re-authenticate?

**A:** Cookie names changed to fix multi-realm bugs. The old cookies won't be recognized by the new version.

### Q: Will users lose their data or preferences?

**A:** No. Only session data (authentication state) is cleared. Application data is unaffected.

### Q: How long does re-authentication take?

**A:** A few seconds - users just need to log in through their OIDC provider again.

### Q: Can I migrate gradually?

**A:** No. This is an all-or-nothing upgrade due to cookie naming changes. However, you can test thoroughly in staging first.

### Q: What if I only use one realm?

**A:** You still benefit from the fixes! Single-realm deployments work as before, just with safer session handling.

### Q: Do I need to change my Traefik configuration?

**A:** No configuration changes required. The plugin handles everything internally.

### Q: Will this affect my token refresh logic?

**A:** No. Token refresh works the same way, just with better error handling.

---

## Support

### Reporting Issues

If you encounter problems after upgrading:

1. **Check logs** for specific error messages
2. **Verify configuration** matches requirements
3. **Test in isolation** (disable other middlewares temporarily)
4. **Report issue**: https://github.com/lukaszraczylo/traefikoidc/issues

Include:
- Traefik version
- Plugin version
- Relevant logs (redact secrets!)
- Steps to reproduce

### Community

- GitHub Issues: https://github.com/lukaszraczylo/traefikoidc/issues
- Documentation: https://github.com/lukaszraczylo/traefikoidc

---

## Summary

✅ **Benefits of Upgrading:**
- Multi-realm support finally works correctly
- Better error handling prevents panics
- More secure (removed test bypass)
- Cookie collision prevention for long instance names

⚠️ **One-time Cost:**
- Users need to re-authenticate once

🎯 **Recommended for:**
- All users, especially those with multi-realm setups
- Anyone experiencing "authentication works for first realm only" issues
- Security-conscious deployments

---

**Version:** 1.0
**Date:** 2025-10-30
**Plugin Version:** v0.8.0
