// Package utils provides common utility functions used across the OIDC middleware
package utils

import (
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

// BuildFullURL constructs a URL from scheme, host, and path components
func BuildFullURL(scheme, host, path string) string {
	return scheme + "://" + host + path
}
