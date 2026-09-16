package traefikoidc

import (
	"testing"
	"time"
)

// TestBearerIntrospection_RefreshTokenTypeRejected guards the R149 fix in
// introspectOnBearerPath: RFC 7662 TokenType is the only classifier for
// an opaque credential (no JWT header). An active introspection result
// whose token_type is a refresh token must not be honored as a bearer
// access token.
func TestBearerIntrospection_RefreshTokenTypeRejected(t *testing.T) {
	refresh := &IntrospectionResponse{Active: true, TokenType: "refresh_token"}
	tObj := &TraefikOidc{
		introspectionCache: &stubIntrospectionCache{v: refresh},
		logger:             newNoOpLogger(),
		clientID:           "client-abc", // audience == "" so no audience discriminator
	}
	if bErr := tObj.introspectOnBearerPath("tok"); bErr == nil {
		t.Fatal("an active introspection result classified as a refresh token must be rejected on the bearer path")
	}
}

// TestBearerIntrospection_AccessTokenTypeAccepted guards the positive side:
// a proper access_token type (and an omitted one) must still pass.
func TestBearerIntrospection_AccessTokenTypeAccepted(t *testing.T) {
	for name, tt := range map[string]string{
		"access_token": "access_token",
		"omitted":      "",
	} {
		t.Run(name, func(t *testing.T) {
			resp := &IntrospectionResponse{Active: true, TokenType: tt, Aud: "https://api.example.com"}
			tObj := &TraefikOidc{
				introspectionCache: &stubIntrospectionCache{v: resp},
				logger:             newNoOpLogger(),
				clientID:           "client-abc",
				audience:           "https://api.example.com",
			}
			if bErr := tObj.introspectOnBearerPath("tok"); bErr != nil {
				t.Fatalf("an active access-token/introspection result must pass, got: %v", bErr)
			}
		})
	}
}

// TestOpaqueToken_RefreshTokenTypeRejected guards the session-path
// (validateOpaqueToken) counterpart of the same R149 fix.
func TestOpaqueToken_RefreshTokenTypeRejected(t *testing.T) {
	refresh := &IntrospectionResponse{Active: true, TokenType: "refresh_token"}
	tObj := &TraefikOidc{
		introspectionCache: &stubIntrospectionCache{v: refresh},
		logger:             newNoOpLogger(),
		clientID:           "client-abc", // audience == "" so no audience discriminator
		allowOpaqueTokens:  true,
		introspectionURL:   "https://introspect.example.com/introspect",
	}
	if err := tObj.validateOpaqueToken("tok"); err == nil {
		t.Fatal("an opaque refresh token must be rejected by validateOpaqueToken (token_type mismatch)")
	}
}

// TestBackgroundTask_ZeroIntervalNoPanic guards the R149 fix in
// NewBackgroundTask: run() calls time.NewTicker(interval), which panics
// for interval <= 0 inside the started goroutine, crashing the whole
// process. Non-positive intervals are now normalized at construction.
func TestBackgroundTask_ZeroIntervalNoPanic(t *testing.T) {
	bt := NewBackgroundTask("r149-zero", 0, func() {}, newNoOpLogger())
	bt.Start()
	// Give the goroutine time to reach NewTicker; on the un-fixed code
	// this panics and crashes the test process.
	time.Sleep(20 * time.Millisecond)
	bt.Stop()

	bt2 := NewBackgroundTask("r149-normal", time.Hour, func() {}, newNoOpLogger())
	bt2.Start()
	time.Sleep(5 * time.Millisecond)
	bt2.Stop()
}
