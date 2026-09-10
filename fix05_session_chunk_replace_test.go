package traefikoidc

// Regression tests for FIX-05 (review-2026-09-10 finding at session.go:2409,
// session.go:3099): SetRefreshToken/SetIDToken re-Get the gorilla-registry-
// cached chunk *sessions.Session objects for the NEW token, fill them, and
// only THEN call the expire helper for the OLD chunks. Because gorilla's
// Registry.Get returns the SAME cached object per cookie name for a given
// request, the "expire old" pass re-Gets those identical objects and wipes
// session.Values on every non-new one -- erasing the NEW chunk data this
// call just wrote. A session loaded from existing (legacy) chunk cookies
// whose replacement token also needs chunking loses the new token entirely.
//
// Adapted from the throwaway repro at
// .claude/review-2026-09-10/repro/zz_g1_chunkwipe_test.go and
// zz_g1_chunkwipe_id_test.go (TestG1ChunkWipeRefresh / TestG1ChunkWipeAccessControl
// / TestG1ChunkWipeIDToken), renamed to describe the behavior they pin.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// randChunkTestToken returns a random URL-safe token of n raw bytes, large
// enough (with maxCookieSize=1400) to force the chunked storage path.
func randChunkTestToken(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// randChunkTestJWT returns a structurally valid (3-dot-separated) JWT whose
// payload is padded past maxCookieSize, so SetIDToken takes the chunked path.
func randChunkTestJWT(t *testing.T) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256","typ":"JWT","kid":"k"}`))
	now := time.Now().Unix()
	payload := enc([]byte(fmt.Sprintf(
		`{"iss":"https://idp","sub":"u","aud":"c","iat":%d,"exp":%d,"pad":"%s"}`,
		now, now+3600, randChunkTestToken(t, 3000),
	)))
	return header + "." + payload + "." + randChunkTestToken(t, 256)
}

// mergeSetCookiesIntoJar copies a response's Set-Cookie headers into jar,
// dropping any cookie the response expired (MaxAge < 0), so the next request
// carries forward only what a real browser would still hold.
func mergeSetCookiesIntoJar(jar map[string]*http.Cookie, rr *httptest.ResponseRecorder) {
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(jar, c.Name)
			continue
		}
		jar[c.Name] = c
	}
}

// newRequestWithJarCookies builds a request carrying every cookie currently
// held in jar, simulating a browser replaying its cookie jar on the next
// request to the same session.
func newRequestWithJarCookies(jar map[string]*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	for _, c := range jar {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

// runChunkedTokenReplaceRegression drives three requests against one
// SessionManager: request 1 stores a large (chunked) token A and saves it,
// request 2 loads the cookies A produced and replaces the token with a
// different large (chunked) token B, request 3 loads the cookies B produced
// and must read back B, not A and not empty.
func runChunkedTokenReplaceRegression(
	t *testing.T,
	set func(*SessionData, string),
	get func(*SessionData) string,
	tokA, tokB string,
) {
	t.Helper()
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	jar := map[string]*http.Cookie{}

	r1 := newRequestWithJarCookies(jar)
	s1, err := sm.GetSession(r1)
	if err != nil {
		t.Fatalf("GetSession (request 1): %v", err)
	}
	set(s1, tokA)
	rr1 := httptest.NewRecorder()
	if err := s1.Save(r1, rr1); err != nil {
		t.Fatalf("Save (request 1): %v", err)
	}
	s1.returnToPoolSafely()
	mergeSetCookiesIntoJar(jar, rr1)

	r2 := newRequestWithJarCookies(jar)
	s2, err := sm.GetSession(r2)
	if err != nil {
		t.Fatalf("GetSession (request 2): %v", err)
	}
	if got := get(s2); got != tokA {
		t.Fatalf("request 2 must load token A written by request 1 before replacing it: got len=%d, want tokA", len(got))
	}
	set(s2, tokB)
	if got := get(s2); got != tokB {
		t.Fatalf("in-memory read immediately after replacing the chunked token must return the NEW token: got len=%d (isA=%v), want tokB", len(got), got == tokA)
	}
	rr2 := httptest.NewRecorder()
	if err := s2.Save(r2, rr2); err != nil {
		t.Fatalf("Save (request 2): %v", err)
	}
	s2.returnToPoolSafely()
	mergeSetCookiesIntoJar(jar, rr2)

	r3 := newRequestWithJarCookies(jar)
	s3, err := sm.GetSession(r3)
	if err != nil {
		t.Fatalf("GetSession (request 3): %v", err)
	}
	defer s3.returnToPoolSafely()
	got := get(s3)
	if got != tokB {
		t.Fatalf("after replacing a chunked token loaded from cookies: got len=%d (isTokA=%v), want tokB (the user would be silently signed out)", len(got), got == tokA)
	}
}

// TestSessionData_SetRefreshToken_ReplacesChunkedTokenLoadedFromCookies pins
// FIX-05 (session.go:2409): replacing a chunked refresh token that was
// loaded from existing chunk cookies must not wipe the newly written chunks.
func TestSessionData_SetRefreshToken_ReplacesChunkedTokenLoadedFromCookies(t *testing.T) {
	tokA := randChunkTestToken(t, 4500)
	tokB := randChunkTestToken(t, 4500)
	runChunkedTokenReplaceRegression(
		t,
		func(s *SessionData, v string) { s.SetRefreshToken(v) },
		func(s *SessionData) string { return s.GetRefreshToken() },
		tokA, tokB,
	)
}

// TestSessionData_SetIDToken_ReplacesChunkedTokenLoadedFromCookies pins
// FIX-05 (session.go:3099): the same bug in SetIDToken, using structurally
// valid JWTs since SetIDToken rejects non-JWT-shaped input.
func TestSessionData_SetIDToken_ReplacesChunkedTokenLoadedFromCookies(t *testing.T) {
	tokA := randChunkTestJWT(t)
	tokB := randChunkTestJWT(t)
	runChunkedTokenReplaceRegression(
		t,
		func(s *SessionData, v string) { s.SetIDToken(v) },
		func(s *SessionData) string { return s.GetIDToken() },
		tokA, tokB,
	)
}

// TestSessionData_SetAccessToken_ReplacesChunkedTokenLoadedFromCookies is the
// control: SetAccessToken already uses the expire-then-fill order (it was
// unaffected by the R154 regression) and must stay green both before and
// after FIX-05, proving the fix does not depend on a shared helper bug.
func TestSessionData_SetAccessToken_ReplacesChunkedTokenLoadedFromCookies(t *testing.T) {
	tokA := randChunkTestToken(t, 4500)
	tokB := randChunkTestToken(t, 4500)
	runChunkedTokenReplaceRegression(
		t,
		func(s *SessionData, v string) { s.SetAccessToken(v) },
		func(s *SessionData) string { return s.GetAccessToken() },
		tokA, tokB,
	)
}
