// Package cache provides the in-memory cache implementation for the Traefik
// OIDC plugin.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// redactKey returns a short, deterministic hash prefix of a cache key for use
// in debug/info log lines. Cache keys may include raw access / refresh / id
// tokens (callers pass arbitrary strings) and CodeQL flags `key=%s`
// formatters as a clear-text-logging sink for HTTP-header-sourced taint.
// The hash preserves uniqueness in logs (same key → same hash) while keeping
// the raw value out of disk-resident log streams.
func redactKey(key string) string {
	if key == "" {
		return "(empty)"
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}
