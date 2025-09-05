package traefikoidc

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Global cleanup after all tests
	globalCleanup.CleanupAll()

	os.Exit(code)
}
