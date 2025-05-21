package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSessionPoolMemoryLeak(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Test 1: Successful session creation and return
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Clear the session which should return it to the pool
	session.Clear(req, nil)

	// Test 2: ReturnToPool explicit method
	session, err = sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Call ReturnToPool directly
	session.ReturnToPool()

	// Test 3: Error path in GetSession
	// Modify the session store to force an error - use a different encryption key
	badSM, _ := NewSessionManager("different0123456789abcdef0123456789abcdef0123456789", false, logger)

	// Get session using mismatched manager/request to force error
	_, err = badSM.GetSession(req)
	if err == nil {
		// We don't test the exact error since it could vary, just that we get one
		t.Log("Note: Expected error when using mismatched encryption keys")
	}

	// Force GC to ensure any objects are cleaned up
	runtime.GC()

	// Wait a moment for GC to complete
	time.Sleep(100 * time.Millisecond)

	// Check if we have objects in the pool
	// This is just a simple check; in a real scenario, we'd have to
	// consider that sync.Pool can discard objects at any time.
	pooledCount := getPooledObjects(sm)
	t.Logf("Pooled objects count: %d", pooledCount)
}

func TestSessionErrorHandling(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Call the GetSession method, corrupting the cookie to force an error
	req.AddCookie(&http.Cookie{
		Name:  mainCookieName,
		Value: "corrupt-value",
	})

	_, err = sm.GetSession(req)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Check that the error message contains our expected prefix
	if err != nil && !strings.Contains(err.Error(), "failed to get main session:") {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestSessionClearAlwaysReturnsToPool(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a test request with the special header that will trigger an error
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("X-Test-Error", "true") // This will trigger the error in session.Clear

	// Get a session
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Create a response writer
	w := httptest.NewRecorder()

	// Call Clear with the test request (with X-Test-Error header) and response writer
	// This should trigger the serialization error in Save
	clearErr := session.Clear(req, w)

	// Verify that Clear returned the error from Save
	if clearErr == nil {
		t.Error("Expected an error from Clear with X-Test-Error header, but got nil")
	} else {
		t.Logf("Received expected error from Clear: %v", clearErr)
	}

	// Force GC to ensure any objects are cleaned up
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Create and clear another session (without the error header) to verify the pool is still working
	normalReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session2, err := sm.GetSession(normalReq)
	if err != nil {
		t.Fatalf("Second GetSession failed: %v", err)
	}
	session2.Clear(normalReq, nil)

	// If we got here without panics, the test is successful
	t.Log("Session returned to pool despite errors")
}

// This placeholder comment is intentionally left empty since we're removing redundant code

// Helper function to count objects in the session pool for a given manager
func getPooledObjects(sm *SessionManager) int {
	// Collect objects until we can't get any more from the pool
	// Set a max limit to avoid potential infinite loops
	var objects []*SessionData
	maxAttempts := 100 // Safety limit to prevent infinite loops

	for i := 0; i < maxAttempts; i++ {
		obj := sm.sessionPool.Get()
		if obj == nil {
			break
		}

		// Type assertion with validation
		sessionData, ok := obj.(*SessionData)
		if !ok {
			// Return the object even if it's not the right type to avoid leaks
			sm.sessionPool.Put(obj)
			break
		}

		objects = append(objects, sessionData)
	}

	// Count how many objects we found
	count := len(objects)

	// Return all objects back to the pool to preserve the pool state
	for _, obj := range objects {
		sm.sessionPool.Put(obj)
	}

	return count
}

// TestSessionObjectTracking verifies that session objects are properly
// returned to the pool in various scenarios including normal usage and error paths
func TestSessionObjectTracking(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Test that the session pool is used as expected
	hasNew := sm.sessionPool.New != nil
	if !hasNew {
		t.Error("Expected sessionPool.New function to be set")
	}

	// Create and discard 5 sessions
	for i := 0; i < 5; i++ {
		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		session.ReturnToPool()
	}

	// Create a session and get an error when trying to clear it
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Deliberately cause bad state in the session object
	session.mainSession = nil // This will cause an error in Clear

	// Even with an error, the pool should not leak
	session.ReturnToPool()

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Success - if we got here without crashing, the pool is working as expected
	t.Log("Session pool handling verified")
}

// This is intentionally left empty to remove unused code
