// Package backends provides cache backend implementations for the Traefik OIDC plugin.
package backends

import (
	"crypto/sha256"
	"encoding/hex"
)

// redactKey returns a short, deterministic hash prefix of a cache key for use
// in debug/info log lines. Cache keys in this plugin can include raw access /
// refresh / id tokens (any caller may pass an arbitrary string), and CodeQL
// flags `key=%s` formatters as a clear-text-logging sink for HTTP-header-
// sourced taint. The hash preserves cache-key uniqueness in logs (same key →
// same hash, useful for correlating a problematic key across log lines) while
// keeping the raw value out of disk-resident log streams.
//
// 8 hex chars (32 bits) is enough to disambiguate at human-debugging scale
// without making the hash itself a useful lookup primitive for an attacker
// who only has the log stream.
func redactKey(key string) string {
	if key == "" {
		return "(empty)"
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}
