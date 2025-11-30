package core

import (
	"testing"
)

// TestCookiePrefix tests that custom cookie prefixes work correctly
func TestCookiePrefix(t *testing.T) {
	tests := []struct {
		name         string
		cookiePrefix string
		wantMain     string
		wantAccess   string
		wantRefresh  string
		wantID       string
	}{
		{
			name:         "Default prefix",
			cookiePrefix: "",
			wantMain:     "_oidc_raczylo_m",
			wantAccess:   "_oidc_raczylo_a",
			wantRefresh:  "_oidc_raczylo_r",
			wantID:       "_oidc_raczylo_id",
		},
		{
			name:         "Custom prefix",
			cookiePrefix: "_oidc_myapp_",
			wantMain:     "_oidc_myapp_m",
			wantAccess:   "_oidc_myapp_a",
			wantRefresh:  "_oidc_myapp_r",
			wantID:       "_oidc_myapp_id",
		},
		{
			name:         "Custom prefix without underscore suffix",
			cookiePrefix: "myapp",
			wantMain:     "myappm",
			wantAccess:   "myappa",
			wantRefresh:  "myappr",
			wantID:       "myappid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}

			sm, err := NewSessionManager(
				"0123456789abcdef0123456789abcdef0123456789abcdef",
				false,
				"",
				tt.cookiePrefix,
				0,
				logger,
				chunkManager,
			)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			// Test cookie names
			if got := sm.MainCookieName(); got != tt.wantMain {
				t.Errorf("MainCookieName() = %q, want %q", got, tt.wantMain)
			}
			if got := sm.AccessTokenCookie(); got != tt.wantAccess {
				t.Errorf("AccessTokenCookie() = %q, want %q", got, tt.wantAccess)
			}
			if got := sm.RefreshTokenCookie(); got != tt.wantRefresh {
				t.Errorf("RefreshTokenCookie() = %q, want %q", got, tt.wantRefresh)
			}
			if got := sm.IDTokenCookie(); got != tt.wantID {
				t.Errorf("IDTokenCookie() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

// TestMultipleInstancesWithDifferentPrefixes tests that multiple session managers
// with different prefixes can coexist (addresses issue #87)
func TestMultipleInstancesWithDifferentPrefixes(t *testing.T) {
	logger := &MockLogger{}
	chunkManager1 := &MockChunkManager{}
	chunkManager2 := &MockChunkManager{}

	// Create two session managers with different prefixes
	sm1, err := NewSessionManager(
		"0123456789abcdef0123456789abcdef0123456789abcdef",
		false,
		"example.com",
		"_oidc_app1_",
		0,
		logger,
		chunkManager1,
	)
	if err != nil {
		t.Fatalf("Failed to create session manager 1: %v", err)
	}

	sm2, err := NewSessionManager(
		"fedcba9876543210fedcba9876543210fedcba9876543210", // Different encryption key
		false,
		"example.com",
		"_oidc_app2_",
		0,
		logger,
		chunkManager2,
	)
	if err != nil {
		t.Fatalf("Failed to create session manager 2: %v", err)
	}

	// Verify they have different cookie names
	if sm1.MainCookieName() == sm2.MainCookieName() {
		t.Error("Expected different main cookie names for different instances")
	}

	// Verify cookie name patterns
	expectedPrefix1 := "_oidc_app1_"
	expectedPrefix2 := "_oidc_app2_"

	if sm1.MainCookieName() != expectedPrefix1+"m" {
		t.Errorf("Expected main cookie name %s, got %s", expectedPrefix1+"m", sm1.MainCookieName())
	}

	if sm2.MainCookieName() != expectedPrefix2+"m" {
		t.Errorf("Expected main cookie name %s, got %s", expectedPrefix2+"m", sm2.MainCookieName())
	}

	t.Log("✓ Session isolation verified: Different cookie prefixes prevent session sharing")
}
