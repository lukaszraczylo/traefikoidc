package traefikoidc

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
)

// TestSetCodeVerifier_NoChange tests the branch where the code verifier value doesn't change
func TestSetCodeVerifier_NoChange(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Set initial code verifier
	initialVerifier := "test-code-verifier-12345"
	session.SetCodeVerifier(initialVerifier)

	if !session.IsDirty() {
		t.Error("Session should be dirty after first SetCodeVerifier")
	}

	// Mark clean to test the no-change branch
	session.dirty = false

	// Set the same code verifier again - this should hit the uncovered branch
	session.SetCodeVerifier(initialVerifier)

	// Verify that dirty flag remains false (no change occurred)
	if session.IsDirty() {
		t.Error("Session should not be dirty when setting same code verifier value")
	}

	// Verify the code verifier value is still correct
	if got := session.GetCodeVerifier(); got != initialVerifier {
		t.Errorf("Expected code verifier %q, got %q", initialVerifier, got)
	}
}

// TestClearTokenChunks_EmptyChunks tests the branch where the chunks map is empty
func TestClearTokenChunks_EmptyChunks(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Test with empty chunks map - this should hit the uncovered branch where the loop body doesn't execute
	emptyChunks := make(map[int]*sessions.Session)

	// This should not panic and should handle empty map gracefully
	session.clearTokenChunks(req, emptyChunks)

	// Verify that no errors occurred and the session is still valid
	if session == nil {
		t.Fatal("Session should still be valid after clearing empty chunks")
	}

	// Additional test: clear already-empty chunk maps in the session
	session.clearTokenChunks(req, session.accessTokenChunks)
	session.clearTokenChunks(req, session.refreshTokenChunks)
	session.clearTokenChunks(req, session.idTokenChunks)

	// Verify session is still valid
	if session.GetAuthenticated() {
		// This is fine - session can be authenticated even with no chunks
	}
}

// TestClearTokenChunks_WithSessions tests the branch where the chunks map contains actual sessions
func TestClearTokenChunks_WithSessions(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Create chunks map with actual sessions
	chunksWithSessions := make(map[int]*sessions.Session)

	// Create a few test sessions and add them to the chunks map
	for i := 0; i < 3; i++ {
		chunkSession, err := sm.store.Get(req, fmt.Sprintf("test_chunk_%d", i))
		if err != nil {
			t.Fatalf("Failed to create test chunk session: %v", err)
		}
		// Add some test data to the session
		chunkSession.Values["test_data"] = fmt.Sprintf("chunk_%d_data", i)
		chunkSession.Values["chunk_index"] = i
		chunksWithSessions[i] = chunkSession
	}

	// Verify chunks have data before clearing
	if len(chunksWithSessions) != 3 {
		t.Errorf("Expected 3 chunks, got %d", len(chunksWithSessions))
	}

	for i, chunkSession := range chunksWithSessions {
		if chunkSession.Values["test_data"] == nil {
			t.Errorf("Chunk %d should have test data before clearing", i)
		}
	}

	// Call clearTokenChunks - this should hit the loop body and clear all sessions
	session.clearTokenChunks(req, chunksWithSessions)

	// Verify that the sessions were cleared
	for i, chunkSession := range chunksWithSessions {
		if len(chunkSession.Values) != 0 {
			t.Errorf("Chunk %d should have no values after clearing, but has %d values", i, len(chunkSession.Values))
		}
		// Verify MaxAge was set to -1 (expired)
		if chunkSession.Options.MaxAge != -1 {
			t.Errorf("Chunk %d should have MaxAge=-1 (expired), but has MaxAge=%d", i, chunkSession.Options.MaxAge)
		}
	}
}
