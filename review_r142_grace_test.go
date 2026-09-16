package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGraceSkipDoesNotForwardUnauthenticated verifies that the grace-period
// refresh-skip only bare-forwards a session that is genuinely
// authenticated. skipRefreshForTokens only parseJWT's the token and reads
// the raw exp claim — it does not verify the signature or identity, so an
// unauthenticated session carrying a still-valid (future-exp) token must not
// be forwarded past the auth gate by the grace fast-path (R142).
//
// Setup: an UNAUTHENTICATED session (SetAuthenticated left at its default
// false) holding a refresh token and a future-exp ID token whose exp is
// outside the grace window. shouldSkipGraceRefresh is true, but because
// authenticated == false the new gate falls through to the refresh path
// instead of bare-forwarding.
func TestGraceSkipDoesNotForwardUnauthenticated(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	nextCalled := false
	oidc := &TraefikOidc{
		next:                         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true }),
		logger:                       newNoOpLogger(),
		initComplete:                 make(chan struct{}),
		sessionManager:               sessionManager,
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
		extractClaimsFunc:            extractClaims,
		audience:                     "test-client",
	}
	close(oidc.initComplete)

	now := time.Now()
	// Well-formed 3-segment JWT with future exp and proper claims. It is
	// NOT signature-verifiable (junk signature), but parseJWT succeeds and
	// forwardAuthorized only decodes claims, so it is enough for the skip
	// decision and for the forwarding pipeline.
	payload, _ := json.Marshal(map[string]any{
		"exp": float64(now.Add(time.Hour).Unix()),
		"iat": float64(now.Add(-time.Minute).Unix()),
		"sub": "user@example.com",
	})
	junkSig := base64.RawURLEncoding.EncodeToString([]byte("this-is-not-a-valid-signature-ful"))
	idToken := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + "." + junkSig

	req0 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw0 := httptest.NewRecorder()
	sess, err := sessionManager.GetSession(req0)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	sess.SetUserIdentifier("user@example.com")
	sess.SetIDToken(idToken)
	sess.SetRefreshToken("refresh-token")
	sess.MarkDirty()
	if err := sess.Save(req0, rw0); err != nil {
		t.Fatalf("save session: %v", err)
	}
	sess.returnToPoolSafely()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range rw0.Result().Cookies() {
		req.AddCookie(c)
	}
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if nextCalled {
		t.Fatal("unauthenticated session with a future-exp token must not be bare-forwarded by the grace skip (auth gate bypass)")
	}
}
