package traefikoidc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDefaultInitiateAuthentication_DebugLogsOmitStateAndNonce pins FIX-29:
// login initiation must not log the CSRF/state token or the nonce in the
// clear at Debug, despite the R153 commit claiming "redaction of ...
// state in logs". At head, "Session saved before redirect. CSRF: %s,
// Nonce: %s" logs both verbatim, and "Redirecting user to OIDC provider:
// %s" logs the full authorize URL (state and nonce as query values).
func TestDefaultInitiateAuthentication_DebugLogsOmitStateAndNonce(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		NewLogger("debug"),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	logger := NewLogger("debug")
	var logBuf bytes.Buffer
	logger.logDebug.SetOutput(&logBuf)

	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         logger,
		issuerURL:      "https://auth.example.com",
		clientID:       "test-client-id",
		scopes:         []string{"openid", "email"},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected/resource", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer session.returnToPoolSafely()

	oidc.defaultInitiateAuthentication(rw, req, session, "https://myapp.com/callback")

	if rw.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to the provider, got %d: %s", rw.Code, rw.Body.String())
	}

	csrf := session.GetCSRF()
	nonce := session.GetNonce()
	if csrf == "" || nonce == "" {
		t.Fatalf("expected session to carry a generated CSRF/nonce, got csrf=%q nonce=%q", csrf, nonce)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, csrf) {
		t.Fatalf("debug logs must not contain the CSRF/state value %q, got: %s", csrf, logOutput)
	}
	if strings.Contains(logOutput, nonce) {
		t.Fatalf("debug logs must not contain the nonce value %q, got: %s", nonce, logOutput)
	}
}
