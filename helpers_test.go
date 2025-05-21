package traefikoidc

import (
	"crypto/rand"
	"encoding/hex"
)

// generateRandomString generates a random string of the specified length
// This is used in tests to create unique identifiers
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// In tests, fallback to a predictable string if random fails
		return "random-string-fallback"
	}
	return hex.EncodeToString(bytes)
}
