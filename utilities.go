// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains utility/helper methods extracted from main.go for better code organization.
package traefikoidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// metadataSnap returns the most recently published *MetadataSnapshot, or nil
// if metadata has not yet been resolved. Single atomic.Value.Load — the hot
// ServeHTTP path uses this instead of acquiring metadataMu.RLock, which under
// Yaegi pays 1-5ms of interpreter-dispatch overhead per acquisition.
func (t *TraefikOidc) metadataSnap() *MetadataSnapshot {
	v := t.metadataSnapshot.Load()
	if v == nil {
		return nil
	}
	s, _ := v.(*MetadataSnapshot)
	return s
}

// safeLogDebug provides nil-safe logging for debug messages
func (t *TraefikOidc) safeLogDebug(msg string) {
	if t.logger != nil {
		t.logger.Debug("%s", msg)
	}
}

// safeLogDebugf provides nil-safe logging for formatted debug messages
func (t *TraefikOidc) safeLogDebugf(format string, args ...interface{}) {
	if t.logger != nil {
		t.logger.Debugf(format, args...)
	}
}

// safeLogError provides nil-safe logging for error messages
func (t *TraefikOidc) safeLogError(msg string) {
	if t.logger != nil {
		t.logger.Error("%s", msg)
	}
}

// safeLogErrorf provides nil-safe logging for formatted error messages
func (t *TraefikOidc) safeLogErrorf(format string, args ...interface{}) {
	if t.logger != nil {
		t.logger.Errorf(format, args...)
	}
}

// safeLogInfo provides nil-safe logging for info messages
func (t *TraefikOidc) safeLogInfo(msg string) {
	if t.logger != nil {
		t.logger.Info("%s", msg)
	}
}

// isAllowedUser checks if a user identifier is authorized based on the configured user identifier claim.
// When using email as the identifier (default), it validates against allowedUsers and allowedUserDomains.
// When using non-email identifiers (sub, oid, upn, etc.), it only validates against allowedUsers
// since domain-based validation doesn't apply to non-email identifiers.
//
// Parameters:
//   - userIdentifier: The user identifier to validate (email, sub, oid, upn, etc.).
//
// Returns:
//   - true if the user is authorized, false otherwise.
func (t *TraefikOidc) isAllowedUser(userIdentifier string) bool {
	// If no restrictions are configured, allow all authenticated users
	if len(t.allowedUserDomains) == 0 && len(t.allowedUsers) == 0 {
		return true
	}

	// Check if user is explicitly allowed
	if len(t.allowedUsers) > 0 {
		_, userAllowed := t.allowedUsers[strings.ToLower(userIdentifier)]
		if userAllowed {
			t.logger.Debugf("User identifier %s is explicitly allowed in allowedUsers", userIdentifier)
			return true
		}
	}

	// For email-based identifiers, also check domain restrictions
	// Only apply domain validation if using email as identifier AND identifier looks like an email
	if t.userIdentifierClaim == "email" && strings.Contains(userIdentifier, "@") {
		return t.isAllowedDomain(userIdentifier)
	}

	// For non-email identifiers with allowedUserDomains configured, log a warning
	if len(t.allowedUserDomains) > 0 && t.userIdentifierClaim != "email" {
		t.logger.Debugf("AllowedUserDomains is configured but userIdentifierClaim is '%s', not 'email'. Domain validation skipped for: %s",
			t.userIdentifierClaim, userIdentifier)
	}

	// User not found in allowedUsers list
	if len(t.allowedUsers) > 0 {
		t.logger.Debugf("User identifier %s is not in the allowed users list", userIdentifier)
	}

	return false
}

// isAllowedDomain checks if an email address is authorized based on domain or user whitelist.
// It validates against both allowed user domains and specific allowed users.
// Parameters:
//   - email: The email address to validate.
//
// Returns:
//   - true if the email is authorized (domain or user allowed), false if not authorized
//     or if the email format is invalid.
func (t *TraefikOidc) isAllowedDomain(email string) bool {
	if len(t.allowedUserDomains) == 0 && len(t.allowedUsers) == 0 {
		return true
	}

	if len(t.allowedUsers) > 0 {
		_, userAllowed := t.allowedUsers[strings.ToLower(email)]
		if userAllowed {
			t.logger.Debugf("Email %s is explicitly allowed in allowedUsers", email)
			return true
		}
	}

	if len(t.allowedUserDomains) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) != 2 {
			t.logger.Errorf("Invalid email format encountered: %s", email)
			return false
		}

		domain := strings.ToLower(parts[1])
		if t.domainAllowed(domain) {
			t.logger.Debugf("Email domain %s is allowed", domain)
			return true
		} else {
			t.logger.Debugf("Email domain %s is NOT allowed. Allowed domains: %v",
				domain, keysFromMap(t.allowedUserDomains))
		}
	} else if len(t.allowedUsers) > 0 {
		t.logger.Debugf("Email %s is not in the allowed users list: %v",
			email, keysFromMap(t.allowedUsers))
	}

	return false
}

// domainAllowed reports whether domain is an allowed user domain,
// including subdomains thereof. An operator configuring
// "example.com" intends to cover staff on corporate subdomains, so
// "mail.example.com" (and deeper) must be accepted; exact match is
// no longer the only path. A plain suffix lookup is avoided (would
// also match "badexample.com"), so subdomains require a leading "."
// separator. (R152)
func (t *TraefikOidc) domainAllowed(domain string) bool {
	if _, ok := t.allowedUserDomains[domain]; ok {
		return true
	}
	for allowed := range t.allowedUserDomains {
		if len(domain) > len(allowed) && strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

// emailVerifiedTrue extracts the boolean email_verified claim value,
// claimScalarString returns the string form of a scalar claim value,
// coercing JSON numbers (float64, json.Number, int variants) to their
// decimal string representation so a numeric identifier claim (e.g. a
// numeric sub from a non-conformant IdP) is preserved rather than
// silently dropped. second is false for non-scalar values (maps,
// slices, objects) so callers can treat them as invalid.
func claimScalarString(raw interface{}) (s string, ok bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	default:
		return "", false
	}
}

// emailVerifiedTrue extracts the boolean email_verified claim value,
// tolerating bool and string representations. present is false when the
// claim is absent or of an uninterpretable type (the caller then decides
// how to treat absence).
func emailVerifiedTrue(v interface{}) (verified, present bool) {
	switch val := v.(type) {
	case bool:
		return val, true
	case string:
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	case float64:
		return val != 0, true
	case json.Number:
		f, err := val.Float64()
		if err != nil {
			return false, false
		}
		return f != 0, true
	}
	return false, false
}

// emailIdentityPermitted reports whether an email-based user identifier may be
// admitted for email/domain authorization given the ID-token claims. An email
// is admitted unless the IdP explicitly marks it unverified
// (email_verified == false): such an address must not satisfy an email
// allowlist, since the user may not control it (impersonation within an
// allowed domain). Absence is tolerated for backward compatibility (the
// middleware and its test fixtures have long run without the claim; some IdPs
// do not emit it). This matches the bearer-path stance that untrusted email
// is a spoofing vector (main.go).
func emailIdentityPermitted(userIdentifier string, claims map[string]interface{}) bool {
	if !strings.Contains(userIdentifier, "@") {
		return true
	}
	if verified, present := emailVerifiedTrue(claims["email_verified"]); present && !verified {
		return false
	}
	return true
}

// keysFromMap extracts string keys from a map for logging purposes.
// Helper function to get keys from a map for logging.
// Parameters:
//   - m: The map to extract keys from.
//
// Returns:
//   - A slice of string keys.
func keysFromMap(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// sendErrorResponse sends an appropriate error response based on the request's Accept header.
// It sends JSON responses for clients that accept JSON, otherwise sends HTML error pages.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request (used to check Accept header).
//   - message: The error message to display.
//   - code: The HTTP status code to set for the response.
func (t *TraefikOidc) sendErrorResponse(rw http.ResponseWriter, req *http.Request, message string, code int) {
	// Auth-failure responses (401/403/429/503) must not be cached by
	// browsers or intermediaries — a cached 401 body would persist across
	// re-authentication (R101).
	rw.Header().Set("Cache-Control", "no-store")
	acceptHeader := req.Header.Get("Accept")

	if strings.Contains(acceptHeader, "application/json") {
		t.logger.Debugf("Sending JSON error response (code %d): %s", code, message)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"error":             http.StatusText(code),
			"error_description": message,
			"status_code":       code,
		}) // Safe to ignore: error response write
		return
	}

	t.logger.Debugf("Sending HTML error response (code %d): %s", code, message)

	returnURL := "/"
	// Escape message to prevent XSS attacks
	escapedMessage := html.EscapeString(message)

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error</title>
    <style>
        body { font-family: sans-serif; padding: 20px; background-color: #f8f9fa; color: #343a40; }
        h1 { color: #dc3545; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Error</h1>
        <p>%s</p>
        <p><a href="%s">Return to application</a></p>
    </div>
</body>
</html>`, escapedMessage, returnURL)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	_, _ = rw.Write([]byte(htmlBody)) // Safe to ignore: error response write
}

// Close gracefully shuts down the TraefikOidc middleware instance.
// It cancels contexts, stops background goroutines, closes HTTP connections,
// cleans up caches, and releases all resources. Safe to call multiple times.
// Returns:
//   - An error if shutdown times out or resource cleanup fails.
func (t *TraefikOidc) Close() error {
	var closeErr error
	t.shutdownOnce.Do(func() {
		t.safeLogDebug("Closing TraefikOidc plugin instance")

		// Get resource manager for cleanup
		rm := GetResourceManager()

		// singleton-token-cleanup is a process-global task shared by every plugin
		// instance. Only stop it when the LAST instance is shutting down;
		// otherwise one instance's teardown (e.g. a single config reload) would
		// kill chunked-session/token cleanup for all surviving instances (rank 12).
		lastInstance := unregisterLiveInstance() <= 0
		if lastInstance {
			_ = rm.StopBackgroundTask("singleton-token-cleanup") // best effort, last instance only
		}
		// Stop metadata refresh task using same hash-based name as
		// startMetadataRefresh. The name derives only from providerURL
		// (main.go), so it is SHARED by every live instance pointing at the
		// same provider; stopping it on one instance's Close would kill 2h
		// metadata refresh for its surviving sibling (which never re-registers).
		// Gate on lastInstance, matching singleton-token-cleanup above.
		if lastInstance && t.providerURL != "" {
			hash := sha256.Sum256([]byte(t.providerURL))
			taskName := "singleton-metadata-refresh-" + hex.EncodeToString(hash[:])[0:6]
			_ = rm.StopBackgroundTask(taskName) // Safe to ignore: best effort cleanup
		}

		// Remove reference for this instance
		rm.RemoveReference(t.name)

		if t.cancelFunc != nil {
			t.cancelFunc()
			t.safeLogDebug("Context cancellation signaled to all goroutines")
		}

		// Clean up legacy stop channels if they exist
		if t.tokenCleanupStopChan != nil {
			close(t.tokenCleanupStopChan)
			t.safeLogDebug("tokenCleanupStopChan closed")
		}
		if t.metadataRefreshStopChan != nil {
			close(t.metadataRefreshStopChan)
			t.safeLogDebug("metadataRefreshStopChan closed")
		}

		if t.refreshCoordinator != nil {
			t.refreshCoordinator.Shutdown()
			t.safeLogDebug("refreshCoordinator shut down")
		}

		if t.goroutineWG != nil {
			done := make(chan struct{})
			go func() {
				t.goroutineWG.Wait()
				close(done)
			}()

			select {
			case <-done:
				t.safeLogDebug("All background goroutines stopped gracefully")
			case <-time.After(10 * time.Second):
				t.safeLogError("Timeout waiting for background goroutines to stop")
			}
		} else {
			t.safeLogDebug("No goroutineWG to wait for (likely in test)")
		}

		if t.httpClient != nil {
			if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
				t.safeLogDebug("HTTP client idle connections closed")
			}
		}

		if t.tokenHTTPClient != nil {
			if transport, ok := t.tokenHTTPClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
				t.safeLogDebug("Token HTTP client idle connections closed")
			}
			if t.tokenHTTPClient.Transport != t.httpClient.Transport {
				if transport, ok := t.tokenHTTPClient.Transport.(*http.Transport); ok {
					transport.CloseIdleConnections()
					t.safeLogDebug("Token HTTP client transport closed (separate from main)")
				}
			}
		}

		if t.tokenBlacklist != nil {
			t.tokenBlacklist.Close()
			t.safeLogDebug("tokenBlacklist closed")
		}
		if t.metadataCache != nil {
			t.metadataCache.Close()
			t.safeLogDebug("metadataCache closed")
		}
		if t.tokenCache != nil {
			t.tokenCache.Close()
			t.safeLogDebug("tokenCache closed")
		}

		if t.jwkCache != nil {
			t.jwkCache.Close()
			t.safeLogDebug("t.jwkCache.Close() called as per original instruction.")
		}

		// Shutdown session manager and its background cleanup routines
		if t.sessionManager != nil {
			if err := t.sessionManager.Shutdown(); err != nil {
				t.safeLogErrorf("Error shutting down session manager: %v", err)
			} else {
				t.safeLogDebug("sessionManager shutdown completed")
			}
		}

		// Clean up error recovery manager
		if t.errorRecoveryManager != nil && t.errorRecoveryManager.gracefulDegradation != nil {
			t.errorRecoveryManager.gracefulDegradation.Close()
			t.safeLogDebug("Error recovery manager graceful degradation closed")
		}

		// Stop all process-global background tasks, but ONLY when the last
		// instance is shutting down. The global TaskRegistry holds shared
		// singleton tasks (singleton-token-cleanup, singleton-metadata-refresh-*,
		// memory-monitor); stopping them on any single instance's Close (e.g. one
		// config reload) would kill cleanup for all surviving instances — the same
		// rationale as the targeted StopBackgroundTask above.
		if lastInstance {
			taskRegistry := GetGlobalTaskRegistry()
			taskRegistry.StopAllTasks()
			t.safeLogDebug("All global background tasks stopped")
		}

		// Note: Centralized pool in internal/pool is singleton-managed and doesn't require explicit cleanup
		t.safeLogDebug("Memory pools managed by singleton pattern")

		// Force garbage collection to help with memory cleanup after shutdown
		runtime.GC()
		t.safeLogDebug("Forced garbage collection after shutdown")

		t.safeLogDebug("TraefikOidc plugin instance closed successfully.")
	})
	return closeErr
}
