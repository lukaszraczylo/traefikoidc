package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestSession_RefreshDoesNotResetCreatedAt regresses the absolute
// session-max-age being made sliding: SetAuthenticated(true) was called on
// every token refresh and unconditionally reset created_at to now, so an
// active (or captured-but-refreshable) session never reached the
// configured maximum age. The creation anchor must be set only on the
// unauthenticated->authenticated transition, not on refresh of an
// already-authenticated session.
func TestSession_RefreshDoesNotResetCreatedAt(t *testing.T) {
	sessionManager := createTestSessionManager(t)
	req := httptest.NewRequest("GET", "/", nil)

	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	session.SetUserIdentifier("user@example.com")
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("initial login: %v", err)
	}

	// Simulate a session that is still within its maximum age but was
	// created a while ago (e.g. 2h ago, well under the 24h default
	// maximum). getAuthenticatedUnsafe still considers it valid.
	oldCreated := time.Now().Add(-2 * time.Hour).Unix()
	session.mainSession.Values["created_at"] = oldCreated

	// This is what the refresh path does on success.
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("refresh SetAuthenticated: %v", err)
	}

	got, ok := session.mainSession.Values["created_at"].(int64)
	if !ok {
		t.Fatalf("created_at missing or not int64")
	}
	if got != oldCreated {
		t.Fatalf("refresh advanced created_at: got %d, want %d (old anchor must be preserved)", got, oldCreated)
	}
}
