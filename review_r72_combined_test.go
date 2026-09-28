package traefikoidc

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
)

// TestCombinedChunk_MixedGenerationIndexRejected is a regression for a
// combined-session read-path gap: loadFromCombinedCookies accepted any
// present chunk set without verifying each chunk's own stored index (i) and
// count (n). An interrupted save could leave a mixed-generation cookie set
// that reassembled into valid-looking but wrong session data. The read
// path must now reject a chunk whose metadata disagrees with its cookie
// position (clean re-auth) instead of silently decoding.
func TestCombinedChunk_MixedGenerationIndexRejected(t *testing.T) {
	sm := createTestSessionManager(t)
	defer sm.Shutdown()

	// Build a session large enough to split into multiple combined chunks.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	session.SetUserIdentifier("user@example.com")
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("mark authenticated: %v", err)
	}
	bulk := make([]byte, 8000)
	_, _ = rand.Read(bulk)
	session.mainSession.Values["bulk"] = string(bulk)
	// Force combined storage so the large payload is split into multiple
	// combined chunk cookies (matching the real combined-session path)
	// rather than overflowing the single legacy main cookie.
	session.useCombinedStorage = true
	session.combinedChunks = make(map[int]*sessions.Session)
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("save session: %v", err)
	}
	goodCookies := rw.Result().Cookies()

	// Confirm the save actually produced multiple chunks (so the test is
	// meaningful) by attempting to load chunk 1.
	if _, err := sm.store.Get(req, sm.combinedChunkCookieName(1)); err != nil {
		t.Fatalf("expected a multi-chunk combined session, but chunk 1 is not loadable: %v", err)
	}

	// Control: the original, unmodified cookie set must load.
	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range goodCookies {
		okReq.AddCookie(c)
	}
	okSess, err := sm.GetSession(okReq)
	if err != nil {
		t.Fatalf("get session from original cookies: %v", err)
	}
	if okSess.GetUserIdentifier() != "user@example.com" {
		t.Fatalf("original combined cookie set did not load user identifier")
	}

	// Tamper: rewrite chunk 1 with an index that disagrees with its
	// position, giving a "mixed-generation" set.
	tamperReq := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range goodCookies {
		tamperReq.AddCookie(c)
	}
	ch1, err := sm.store.Get(tamperReq, sm.combinedChunkCookieName(1))
	if err != nil {
		t.Fatalf("get chunk 1 for tampering: %v", err)
	}
	ch1.Values["i"] = 7
	tamperW := httptest.NewRecorder()
	if err := ch1.Save(tamperReq, tamperW); err != nil {
		t.Fatalf("save tampered chunk 1: %v", err)
	}
	loadReq := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range goodCookies {
		if c.Name == sm.combinedChunkCookieName(1) {
			continue // replaced below with the tampered chunk
		}
		loadReq.AddCookie(c)
	}
	for _, c := range tamperW.Result().Cookies() {
		loadReq.AddCookie(c)
	}

	tamperedSess, err := sm.GetSession(loadReq)
	if err != nil {
		t.Fatalf("get session from tampered cookies: %v", err)
	}
	if got := tamperedSess.GetUserIdentifier(); got != "" {
		t.Fatalf("mixed-generation combined cookie set loaded user %q, want clean re-auth (empty)", got)
	}
}
