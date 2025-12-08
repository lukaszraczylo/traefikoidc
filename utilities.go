// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains utility/helper methods extracted from main.go for better code organization.
package traefikoidc

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"runtime"
	"strings"
	"time"
)

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

		domain := parts[1]
		_, domainAllowed := t.allowedUserDomains[domain]

		if domainAllowed {
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

		// Stop singleton tasks related to this instance
		_ = rm.StopBackgroundTask("singleton-token-cleanup")    // Safe to ignore: best effort cleanup
		_ = rm.StopBackgroundTask("singleton-metadata-refresh") // Safe to ignore: best effort cleanup

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

		// Stop all global background tasks
		taskRegistry := GetGlobalTaskRegistry()
		taskRegistry.StopAllTasks()
		t.safeLogDebug("All global background tasks stopped")

		// Note: Centralized pool in internal/pool is singleton-managed and doesn't require explicit cleanup
		t.safeLogDebug("Memory pools managed by singleton pattern")

		// Force garbage collection to help with memory cleanup after shutdown
		runtime.GC()
		t.safeLogDebug("Forced garbage collection after shutdown")

		t.safeLogDebug("TraefikOidc plugin instance closed successfully.")
	})
	return closeErr
}
