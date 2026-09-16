package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSaveCookie_XForwardedProtoCaseInsensitiveSecure guards the R143 fix in
// session.go Save: the X-Forwarded-Proto value driving the Secure attribute
// was compared case-sensitively ("https"). A proxy emitting a non-canonical
// "HTTPS" (or "Https") value silently downgraded the session cookie to a
// non-Secure, transport-unsafe cookie. The check must be
// case-insensitive.
func TestSaveCookie_XForwardedProtoCaseInsensitiveSecure(t *testing.T) {
	sm, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "HTTPS")
	rw := httptest.NewRecorder()

	sess, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	sess.MarkDirty()
	if err := sess.Save(req, rw); err != nil {
		t.Fatalf("save session: %v", err)
	}
	sess.returnToPoolSafely()

	anySecure := false
	for _, c := range rw.Result().Cookies() {
		if c.Secure {
			anySecure = true
			break
		}
	}
	if !anySecure {
		t.Fatal("a non-canonical (uppercase) X-Forwarded-Proto https value must still yield a Secure session cookie")
	}
}

// TestBearerIntrospection_AudienceMismatchRejected guards the R143 fix in
// bearer_auth.go introspectOnBearerPath: the bearer path only checked
// Active + Exp, while the equivalent cookie path (validateOpaqueToken)
// also enforces the configured API audience. A token minted for a
// different audience could pass the bearer path while the identical token
// was rejected on the session path. Mirror the audience check.
func TestBearerIntrospection_AudienceMismatchRejected(t *testing.T) {
	mismatched := &IntrospectionResponse{Active: true, Aud: "https://other-aud.example.com"}
	tObj := &TraefikOidc{
		introspectionCache: &stubIntrospectionCache{v: mismatched},
		logger:             newNoOpLogger(),
		clientID:           "client-abc",
		audience:           "https://api.example.com",
	}
	if bErr := tObj.introspectOnBearerPath("tok"); bErr == nil {
		t.Fatal("an active introspection result with a mismatched audience must be rejected on the bearer path")
	}
}

// TestBearerIntrospection_AudienceMatchAccepted guards the positive side:
// a matching audience must still be accepted (no regression for valid
// tokens).
func TestBearerIntrospection_AudienceMatchAccepted(t *testing.T) {
	matched := &IntrospectionResponse{Active: true, Aud: "https://api.example.com"}
	tObj := &TraefikOidc{
		introspectionCache: &stubIntrospectionCache{v: matched},
		logger:             newNoOpLogger(),
		clientID:           "client-abc",
		audience:           "https://api.example.com",
	}
	if bErr := tObj.introspectOnBearerPath("tok"); bErr != nil {
		t.Fatalf("an active introspection result with a MATCHING audience must pass, got: %v", bErr)
	}
}
