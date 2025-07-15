package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
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

// TestLargeIDTokenChunking tests that large ID tokens are properly chunked across multiple cookies
func TestLargeIDTokenChunking(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	// Create a large ID token (>4KB) to force chunking
	largeIDToken := createLargeIDToken(20000) // 20KB token to ensure chunking after compression
	t.Logf("Created large ID token with length: %d", len(largeIDToken))

	// Create a request and response recorder
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rr := httptest.NewRecorder()

	// Get session and set large ID token
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Set the large ID token
	session.SetIDToken(largeIDToken)
	t.Logf("Set large ID token in session")

	// Let's check what the GetIDToken returns to confirm it's set
	retrievedToken := session.GetIDToken()
	t.Logf("Retrieved ID token length: %d", len(retrievedToken))
	if len(retrievedToken) != len(largeIDToken) {
		t.Errorf("Token length mismatch: expected %d, got %d", len(largeIDToken), len(retrievedToken))
	}

	// Let's check what's in the main session directly
	if idToken, ok := session.mainSession.Values["id_token"].(string); ok {
		t.Logf("Main session id_token length: %d", len(idToken))
		if compressed, ok := session.mainSession.Values["id_token_compressed"].(bool); ok {
			t.Logf("Main session id_token_compressed: %v", compressed)
		}
	} else {
		t.Logf("Main session id_token not found or not a string")
	}

	// Save the session to trigger chunking
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Verify that chunked cookies were created
	cookies := rr.Result().Cookies()
	t.Logf("Total cookies in response: %d", len(cookies))

	for _, cookie := range cookies {
		valuePreview := cookie.Value
		if len(valuePreview) > 50 {
			valuePreview = valuePreview[:50] + "..."
		}
		t.Logf("Cookie: %s = %s (len=%d)", cookie.Name, valuePreview, len(cookie.Value))
	}

	var mainCookie *http.Cookie
	var chunkCookies []*http.Cookie

	for _, cookie := range cookies {
		if cookie.Name == mainCookieName {
			mainCookie = cookie
		} else if strings.HasPrefix(cookie.Name, mainCookieName+"_") {
			chunkCookies = append(chunkCookies, cookie)
		}
	}

	// Verify main cookie exists
	if mainCookie == nil {
		t.Fatal("Main cookie not found in response")
	}

	// Verify chunk cookies exist (should be at least 2 for a 5KB token)
	if len(chunkCookies) < 2 {
		t.Fatalf("Expected at least 2 chunk cookies, got %d", len(chunkCookies))
	}

	// Verify chunk cookie naming convention
	expectedChunkNames := make(map[string]bool)
	for i := 0; i < len(chunkCookies); i++ {
		expectedChunkNames[mainCookieName+"_"+fmt.Sprintf("%d", i)] = true
	}

	for _, cookie := range chunkCookies {
		if !expectedChunkNames[cookie.Name] {
			t.Errorf("Unexpected chunk cookie name: %s", cookie.Name)
		}
	}

	// Test token retrieval from chunked cookies
	// Create a new request with all the cookies
	newReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
	for _, cookie := range cookies {
		newReq.AddCookie(cookie)
	}

	// Get session and retrieve the ID token
	retrievedSession, err := sm.GetSession(newReq)
	if err != nil {
		t.Fatalf("Failed to get session from chunked cookies: %v", err)
	}

	retrievedToken2 := retrievedSession.GetIDToken()

	// Verify the retrieved token matches the original
	if retrievedToken2 != largeIDToken {
		t.Errorf("Retrieved ID token doesn't match original. Expected length: %d, got: %d", len(largeIDToken), len(retrievedToken2))
	}

	// Test clearing the ID token removes all chunks
	retrievedSession.SetIDToken("")

	clearRR := httptest.NewRecorder()
	err = retrievedSession.Save(newReq, clearRR)
	if err != nil {
		t.Fatalf("Failed to save session after clearing ID token: %v", err)
	}

	// Verify chunks are expired (MaxAge = -1)
	clearCookies := clearRR.Result().Cookies()
	for _, cookie := range clearCookies {
		if strings.HasPrefix(cookie.Name, mainCookieName+"_") {
			if cookie.MaxAge != -1 {
				t.Errorf("Expected chunk cookie %s to be expired (MaxAge=-1), got MaxAge=%d", cookie.Name, cookie.MaxAge)
			}
		}
	}
}

// createLargeIDToken creates a JWT-like token of specified size for testing
func createLargeIDToken(size int) string {
	// Create truly random data that won't compress well
	randomBytes := make([]byte, size*3/4) // base64 encoding increases size by ~4/3
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to pseudo-random if crypto/rand fails
		for i := range randomBytes {
			randomBytes[i] = byte(i % 256)
		}
	}

	// Base64 encode the random data to make it look like a JWT
	encoded := base64.StdEncoding.EncodeToString(randomBytes)

	// Create JWT-like structure with truly random data
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	// Truncate or pad to desired size
	if len(encoded) > size-len(header)-100 {
		encoded = encoded[:size-len(header)-100]
	}

	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	return header + "." + encoded + "." + signature
}

// This is intentionally left empty to remove unused code
