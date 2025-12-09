// Package utils provides common utility functions used across the OIDC middleware
package utils

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// CreateStringMap creates a map with string keys for efficient lookups
func CreateStringMap(items []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range items {
		result[item] = struct{}{}
	}
	return result
}

// CreateCaseInsensitiveStringMap creates a map with lowercase keys for case-insensitive matching
func CreateCaseInsensitiveStringMap(items []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range items {
		result[strings.ToLower(item)] = struct{}{}
	}
	return result
}

// DeduplicateScopes removes duplicate scopes from a slice
func DeduplicateScopes(scopes []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, scope := range scopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}

// MergeScopes combines default scopes with user-provided scopes, removing duplicates
func MergeScopes(defaultScopes, userScopes []string) []string {
	if len(userScopes) == 0 {
		return append([]string(nil), defaultScopes...)
	}

	seen := make(map[string]bool)
	var result []string

	for _, scope := range defaultScopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	for _, scope := range userScopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	return result
}

// IsTestMode detects if the code is running in a test environment
func IsTestMode() bool {
	if os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS") == "1" {
		return true
	}

	if strings.Contains(os.Args[0], ".test") ||
		strings.Contains(os.Args[0], "go_build_") ||
		os.Getenv("GO_TEST") == "1" ||
		runtime.Compiler == "yaegi" {
		return true
	}

	for _, arg := range os.Args {
		if strings.Contains(arg, "-test") {
			return true
		}
	}

	if runtime.Compiler == "gc" {
		progName := os.Args[0]
		if strings.Contains(progName, "test") ||
			strings.HasSuffix(progName, ".test") ||
			strings.Contains(progName, "__debug_bin") {
			return true
		}
	}

	// Only use runtime stack check as fallback when no explicit test conditions are being controlled
	if os.Getenv("DISABLE_RUNTIME_STACK_CHECK") != "1" &&
		os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS") == "" &&
		os.Getenv("GO_TEST") == "" {
		// Check runtime stack for test functions only as last resort
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stack := string(buf[:n])
		if strings.Contains(stack, "testing.tRunner") ||
			strings.Contains(stack, "testing.(*T)") ||
			strings.Contains(stack, ".test.") {
			return true
		}
	}

	return false
}

// KeysFromMap extracts string keys from a map for logging purposes
func KeysFromMap(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// DetermineScheme determines the URL scheme for building redirect URLs.
// Priority order (highest to lowest):
//  1. forceHTTPS parameter - explicit security requirement
//  2. X-Forwarded-Proto header - proxy/load balancer information
//  3. TLS connection state - direct HTTPS connection
//  4. Default to http
//
// The forceHTTPS parameter ensures redirect URIs use HTTPS even when behind
// proxies/load balancers that may overwrite X-Forwarded-Proto header
// (e.g., AWS ALB terminating TLS).
func DetermineScheme(req *http.Request, forceHTTPS bool) string {
	// Honor forceHTTPS configuration as highest priority
	if forceHTTPS {
		return "https"
	}

	// Check X-Forwarded-Proto header for proxy scenarios
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}

	// Check if connection has TLS
	if req.TLS != nil {
		return "https"
	}

	// Default to http
	return "http"
}

// DetermineHost determines the host for building redirect URLs.
// It checks X-Forwarded-Host header first (for proxy scenarios),
// then falls back to req.Host.
func DetermineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// BuildFullURL constructs a URL from scheme, host, and path components.
// It handles absolute URLs (returning them as-is) and ensures paths have leading slashes.
func BuildFullURL(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}
