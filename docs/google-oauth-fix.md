# Google OAuth Integration Fix

## Problem Overview

The Traefik OIDC plugin encountered an authentication issue when using Google as an OAuth provider. Authentication would fail with the following error:

```
Some requested scopes were invalid. {valid=[openid, https://www.googleapis.com/auth/userinfo.email, https://www.googleapis.com/auth/userinfo.profile], invalid=[offline_access]}
```

This occurred because Google's OAuth implementation differs from the standard OIDC specification in how it handles refresh tokens and offline access.

## Technical Details of the Issue

### Standard OIDC Provider Behavior

Most OpenID Connect (OIDC) providers follow the standard specification, where:
- To obtain a refresh token, clients include the `offline_access` scope in their authorization request
- This allows authenticated sessions to persist beyond the initial access token expiration

### Google's Non-Standard Approach

Google's OAuth implementation deviates from the standard by:
1. Not supporting the `offline_access` scope, instead rejecting it as an invalid scope
2. Requiring the `access_type=offline` query parameter for requesting refresh tokens
3. Needing the `prompt=consent` parameter to consistently issue refresh tokens (especially for repeat authentications)

This difference caused the plugin to fail when configured for Google OAuth, as it was using a standard approach that didn't work with Google's implementation.

## Solution Implementation

The fix involved modifying the authentication flow to specifically handle Google providers:

1. **Google Provider Detection**: Added code to detect if the OIDC provider is Google based on the issuer URL:

```go
// Check if we're dealing with a Google OIDC provider
isGoogleProvider := strings.Contains(t.issuerURL, "google") || 
                   strings.Contains(t.issuerURL, "accounts.google.com")
```

2. **Provider-Specific Auth URL Building**: Modified the `buildAuthURL` function to handle Google and non-Google providers differently:

```go
// Handle offline access differently for Google vs other providers
if isGoogleProvider {
    // For Google, use access_type=offline parameter instead of offline_access scope
    params.Set("access_type", "offline")
    t.logger.Debug("Google OIDC provider detected, added access_type=offline for refresh tokens")

    // Add prompt=consent for Google to ensure refresh token is issued
    params.Set("prompt", "consent")
    t.logger.Debug("Google OIDC provider detected, added prompt=consent to ensure refresh tokens")
} else {
    // For non-Google providers, use the offline_access scope
    hasOfflineAccess := false
    for _, scope := range scopes {
        if scope == "offline_access" {
            hasOfflineAccess = true
            break
        }
    }

    if !hasOfflineAccess {
        scopes = append(scopes, "offline_access")
    }
}
```

3. **Token Refresh Enhancement**: Improved the token refresh logic to better handle Google's behavior, particularly when refresh tokens aren't returned in refresh responses (as Google often uses the same refresh token for multiple requests).

## Why This Approach Works

This solution aligns with Google's OAuth 2.0 documentation which specifies:

1. **Access Type Parameter**: Google's [OAuth 2.0 documentation](https://developers.google.com/identity/protocols/oauth2/web-server#offline) states that to request a refresh token, applications must include `access_type=offline` in the authorization request.

2. **Prompt Parameter**: The [`prompt=consent`](https://developers.google.com/identity/protocols/oauth2/web-server#forceapprovalprompt) parameter forces the consent screen to appear, ensuring a refresh token is issued even if the user has previously granted access.

3. **Scope Validation**: Google strictly validates scopes and rejects non-standard ones like `offline_access`, instead relying on the `access_type` parameter to indicate whether a refresh token should be issued.

By adapting to these Google-specific requirements, the OIDC plugin can now seamlessly work with both standard OIDC providers and Google's OAuth implementation.

## Testing and Verification

Comprehensive tests were implemented to verify the solution:

1. **Provider Detection Test**: Ensures the code correctly identifies Google providers and applies the appropriate parameters.

2. **Auth URL Parameter Tests**: Verifies that:
   - For Google providers: `access_type=offline` and `prompt=consent` are included; `offline_access` scope is NOT included
   - For non-Google providers: `offline_access` scope IS included; `access_type` parameter is NOT added

3. **Token Refresh Tests**: Validates that Google's token refresh process works correctly, including the preservation of refresh tokens when Google doesn't return a new one.

4. **Integration Test**: Tests the complete authentication flow with a mocked Google provider to ensure all components work together seamlessly.

Sample test case (simplified):

```go
t.Run("Google provider detection adds required parameters", func(t *testing.T) {
    // Test buildAuthURL to ensure it adds access_type=offline and prompt=consent for Google
    authURL := tOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

    // Check that access_type=offline was added (not offline_access scope for Google)
    if !strings.Contains(authURL, "access_type=offline") {
        t.Errorf("access_type=offline not added to Google auth URL: %s", authURL)
    }

    // Verify offline_access scope is NOT included for Google providers
    if strings.Contains(authURL, "offline_access") {
        t.Errorf("offline_access scope incorrectly added to Google auth URL: %s", authURL)
    }

    // Check that prompt=consent was added
    if !strings.Contains(authURL, "prompt=consent") {
        t.Errorf("prompt=consent not added to Google auth URL: %s", authURL)
    }
})
```

## Usage Guidance for Developers

When configuring the Traefik OIDC middleware for Google:

1. **Provider URL**: Use `https://accounts.google.com` as the `providerURL` value

2. **Client Configuration**: Create OAuth 2.0 credentials in the Google Cloud Console:
   - Configure the authorized redirect URI to match your `callbackURL` setting
   - Ensure your OAuth consent screen is properly configured (especially if you want long-lived refresh tokens)

3. **Configuration Example**:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-google
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: your-google-client-id.apps.googleusercontent.com
      clientSecret: your-google-client-secret
      sessionEncryptionKey: your-secure-encryption-key-min-32-chars
      callbackURL: /oauth2/callback
      scopes:
        - openid
        - email
        - profile
        # Note: DO NOT manually add offline_access scope for Google
        # The middleware handles this automatically and correctly
```

4. **Troubleshooting**: If sessions still expire prematurely with Google (typically after 1 hour):
   - Ensure your Google Cloud OAuth consent screen is set to "External" and "Production" mode (not "Testing" mode, which limits refresh token validity)
   - Review your application logs with `logLevel: debug` to check for refresh token errors
   - Verify you're using a version of the middleware that includes this fix

## Conclusion

This fix ensures that the Traefik OIDC plugin works seamlessly with Google's OAuth implementation without requiring users to make provider-specific configuration changes. The middleware now intelligently adapts to the provider's requirements, making it more robust and user-friendly while maintaining compatibility with the standard OIDC specification for other providers.