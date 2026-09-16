package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUpdateMetadataEndpoints_PreservesEndpointsOnEmpty guards the R151
// fix to main.go updateMetadataEndpoints: jwks_uri, authorization and
// token endpoints got unconditional assignment from discovery, so a
// refresh document that omitted (or SSRF-blanked) one would wipe the
// live value — permanently breaking signature verification with no
// operator override to recover. Mirror the R124 issuer guard: preserve
// a previously-good value on empty.
func TestUpdateMetadataEndpoints_PreservesEndpointsOnEmpty(t *testing.T) {
	tObj := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		providerURL: "https://provider.example.com",
		jwksURL:     "https://provider.example.com/jwks",
		authURL:     "https://provider.example.com/auth",
		tokenURL:    "https://provider.example.com/token",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{}) // all endpoints empty

	if tObj.jwksURL != "https://provider.example.com/jwks" {
		t.Fatalf("jwksURL must be preserved when discovery is empty, got %q", tObj.jwksURL)
	}
	if tObj.authURL != "https://provider.example.com/auth" {
		t.Fatalf("authURL must be preserved when discovery is empty, got %q", tObj.authURL)
	}
	if tObj.tokenURL != "https://provider.example.com/token" {
		t.Fatalf("tokenURL must be preserved when discovery is empty, got %q", tObj.tokenURL)
	}
}

// TestUpdateMetadataEndpoints_PinsTokenRevocationToProvider guards the
// R151 fix to main.go updateMetadataEndpoints: the token endpoint
// receives the client secret and the revocation endpoint the token +
// client credentials. R151 pinned these to the operator-configured
// provider host to stop a poisoned discovery doc capturing that material
// on an arbitrary public host. R158 relaxed that: mainstream providers
// (Google: accounts.google.com issuer, oauth2.googleapis.com token)
// legitimately split hosts, so pinning broke them. SSRF validation
// (blocking private/loopback/cloud-metadata) is retained as the gate.
func TestUpdateMetadataEndpoints_PinsTokenRevocationToProvider(t *testing.T) {
	// Split-host token/revoke endpoints must now be accepted (R158).
	tObj := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		providerURL: "https://provider.example.com",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{
		TokenURL:  "https://token.example.com/token",
		RevokeURL: "https://token.example.com/revoke",
	})

	if tObj.tokenURL != "https://token.example.com/token" {
		t.Fatalf("split-host token endpoint must be accepted, got %q", tObj.tokenURL)
	}
	if tObj.revocationURL != "https://token.example.com/revoke" {
		t.Fatalf("split-host revocation endpoint must be accepted, got %q", tObj.revocationURL)
	}

	// Same-host endpoints must still be accepted (positive side).
	tObj2 := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		providerURL: "https://provider.example.com",
	}
	tObj2.updateMetadataEndpoints(&ProviderMetadata{
		TokenURL:  "https://provider.example.com/token",
		RevokeURL: "https://provider.example.com/revoke",
	})
	if tObj2.tokenURL != "https://provider.example.com/token" || tObj2.revocationURL != "https://provider.example.com/revoke" {
		t.Fatalf("same-host token/revoke must be accepted, got token=%q revoke=%q", tObj2.tokenURL, tObj2.revocationURL)
	}
}

// TestServeHTTP_BypassStripsAuthorization guards the R151 fix to
// middleware.go: stripAuthorizationHeader (default true) was honored only
// in forwardAuthorized, so the SSE/WebSocket/excluded bypass forwarded a
// raw client-supplied Authorization header verbatim — the same leak R144
// closed for the normal path was left open on the streaming bypass.
func TestServeHTTP_BypassStripsAuthorization(t *testing.T) {
	var captured http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("debug"),
		initComplete:                 make(chan struct{}),
		excludedURLs:                 map[string]struct{}{"/health": {}},
		stripAuthorizationHeader:     true, // default true
		enableBearerAuth:             false,
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
	}
	close(oidc.initComplete)

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Authorization", "Bearer raw-client-token")
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	if captured == nil {
		t.Fatal("expected the bypassed request to reach the backend")
	}
	if got := captured.Get("Authorization"); got != "" {
		t.Fatalf("stripAuthorizationHeader must remove Authorization on the bypass path, got %q", got)
	}
}
