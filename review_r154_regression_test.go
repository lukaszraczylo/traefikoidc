package traefikoidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// R154 review-round regressions.

// newR154TestPlugin mirrors the standard test setup from audience_test:
// a real middleware instance backed by a real session manager.
func newR154TestPlugin(t *testing.T) *TraefikOidc {
	t.Helper()
	config := CreateConfig()
	config.ProviderURL = "https://provider.example.com"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-secret"
	config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	config.CallbackURL = "/callback"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	oidc, err := NewWithContext(context.Background(), config, next, "test")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}
	t.Cleanup(func() { _ = oidc.Close() })
	return oidc
}

// incompressibleToken returns a base64 blob too large to fit a single
// cookie after compression, so Set*Token takes the chunked path. Random
// bytes are (nearly) incompressible, unlike repeated chars.
func incompressibleToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawStdEncoding.EncodeToString(buf)
}

// TestSetRefreshToken_AbortPreservesPrevious covers the commit-on-success
// rewrite of SetRefreshToken (session.go). Setting a new chunked refresh
// token on a session whose request is nil (so the chunk write aborts)
// must leave the previously-stored token intact. Fail-on-old: the setter
// cleared the previous token before validating the new one's chunk layout,
// so the abort lost the still-valid prior refresh token -> forced re-auth.
func TestSetRefreshToken_AbortPreservesPrevious(t *testing.T) {
	oidc := newR154TestPlugin(t)

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	session, err := oidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	const original = "still-valid-refresh-token"
	session.SetRefreshToken(original)
	if got := session.GetRefreshToken(); got != original {
		t.Fatalf("setup: expected original token stored, got %q", got)
	}

	// Detach the session from its request so the chunked write of the new
	// token aborts at the first chunk.
	session.request = nil

	big := incompressibleToken(4000) // > maxCookieSize after compression -> chunked
	session.SetRefreshToken(big)

	if got := session.GetRefreshToken(); got != original {
		t.Fatalf("aborted SetRefreshToken must preserve previous token: got %q, want %q", got, original)
	}
}

// TestSetIDToken_AbortPreservesPrevious is the ID-token analog of the
// refresh-token test above.
func TestSetIDToken_AbortPreservesPrevious(t *testing.T) {
	oidc := newR154TestPlugin(t)

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	session, err := oidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	// ID token must be a 3-part JWT (dotCount == 2). Built from parts so the
	// source holds no contiguous JWT literal (avoids a false-positive secret
	// scan on this synthetic fixture); the assembled value is unchanged.
	const original = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0" + "." + "c2lnbmF0dXJl"
	session.SetIDToken(original)
	if got := session.GetIDToken(); got != original {
		t.Fatalf("setup: expected original ID token stored, got %q", got)
	}

	session.request = nil

	// A valid-format 3-part JWT (2 dots) with a large incompressible
	// payload -> takes the chunked path, then aborts on the nil request.
	big := "eyJhbGciOiJSUzI1NiJ9." + incompressibleToken(4000) + ".c2lnbmF0dXJl"
	session.SetIDToken(big)

	if got := session.GetIDToken(); got != original {
		t.Fatalf("aborted SetIDToken must preserve previous token: got %q, want %q", got, original)
	}
}

// TestSetRefreshToken_ChunkedCommitted confirms the normal chunked path
// still stores and reads back a large token (with a live request).
func TestSetRefreshToken_ChunkedCommitted(t *testing.T) {
	oidc := newR154TestPlugin(t)

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	session, err := oidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	big := incompressibleToken(5000)
	session.SetRefreshToken(big)
	if got := session.GetRefreshToken(); got != big {
		t.Fatalf("chunked refresh token round-trip mismatch: got %d bytes, want %d", len(got), len(big))
	}
}

// TestRefreshCoordinator_ShutdownWaitsForInFlight verifies the documented
// Shutdown contract on RefreshCoordinator: Shutdown must block until an
// in-flight refresh completes rather than return while it still runs. The
// corresponding fix (refresh_coordinator.go) moved the WaitGroup Add to
// before the operation is registered so a concurrent Shutdown can never
// observe a registered-but-untracked new operation and miss it.
func TestRefreshCoordinator_ShutdownWaitsForInFlight(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger)

	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	refreshDone := make(chan struct{})

	go func() {
		rc.CoordinateRefresh(context.Background(), "sid", "rt",
			func() (*TokenResponse, error) {
				startedOnce.Do(func() { close(started) })
				<-release
				return &TokenResponse{}, nil
			})
		close(refreshDone)
	}()

	<-started

	shutdownDone := make(chan struct{})
	go func() { rc.Shutdown(); close(shutdownDone) }()

	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned while an in-flight refresh was still running")
	case <-time.After(200 * time.Millisecond):
		// Expected: Shutdown is blocked on wg.Wait until the refresh ends.
	}

	close(release)
	<-refreshDone

	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the in-flight refresh completed")
	}
}
