package traefikoidc

import (
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// sessionWithIssuedAt builds the smallest SessionData that GetRefreshTokenIssuedAt
// reads from. We can't reuse sessionPool.Get() here because that requires a
// fully initialized SessionManager - overkill for this unit-level check.
func sessionWithIssuedAt(t *testing.T, issuedAt time.Time) *SessionData {
	t.Helper()
	rs := sessions.NewSession(nil, "refresh")
	if !issuedAt.IsZero() {
		rs.Values["issued_at"] = issuedAt.Unix()
	}
	return &SessionData{
		refreshSession:     rs,
		accessTokenChunks:  make(map[int]*sessions.Session),
		refreshTokenChunks: make(map[int]*sessions.Session),
		idTokenChunks:      make(map[int]*sessions.Session),
	}
}

func TestIsRefreshTokenExpired_DisabledWhenAgeZero(t *testing.T) {
	tr := &TraefikOidc{maxRefreshTokenAge: 0}
	sd := sessionWithIssuedAt(t, time.Now().Add(-30*24*time.Hour))
	if tr.isRefreshTokenExpired(sd) {
		t.Fatal("expected isRefreshTokenExpired=false when maxRefreshTokenAge is 0")
	}
}

func TestIsRefreshTokenExpired_LegacySessionWithoutTimestamp(t *testing.T) {
	tr := &TraefikOidc{maxRefreshTokenAge: time.Hour}
	sd := sessionWithIssuedAt(t, time.Time{}) // no issued_at value
	if tr.isRefreshTokenExpired(sd) {
		t.Fatal("expected isRefreshTokenExpired=false when issued_at missing (legacy session)")
	}
}

func TestIsRefreshTokenExpired_WithinWindow(t *testing.T) {
	tr := &TraefikOidc{maxRefreshTokenAge: 6 * time.Hour}
	sd := sessionWithIssuedAt(t, time.Now().Add(-1*time.Hour))
	if tr.isRefreshTokenExpired(sd) {
		t.Fatal("expected isRefreshTokenExpired=false within max age")
	}
}

func TestIsRefreshTokenExpired_BeyondWindow(t *testing.T) {
	tr := &TraefikOidc{maxRefreshTokenAge: 6 * time.Hour}
	sd := sessionWithIssuedAt(t, time.Now().Add(-7*time.Hour))
	if !tr.isRefreshTokenExpired(sd) {
		t.Fatal("expected isRefreshTokenExpired=true beyond max age")
	}
}

func TestIsRefreshTokenExpired_NilGuards(t *testing.T) {
	var tr *TraefikOidc
	if tr.isRefreshTokenExpired(nil) {
		t.Fatal("nil receiver must not panic and must return false")
	}
	tr = &TraefikOidc{maxRefreshTokenAge: time.Hour}
	if tr.isRefreshTokenExpired(nil) {
		t.Fatal("nil session must return false")
	}
}
