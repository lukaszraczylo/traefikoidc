package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestR166_BearerOpaqueWithTwoDotsIntrospected guards the JWT-vs-opaque
// routing gate in handleBearerRequest (bearer_auth.go). Previously the
// gate used only strings.Count(token, ".") == 2, so an opaque token
// that coincidentally contained exactly two dots was routed onto the
// JWT path, its header failed to parse, and it was rejected with 401
// even when requireTokenIntrospection was enabled (whose purpose is
// exactly opaque-token support). The gate now treats a token as a JWT
// only when its header actually parses as a JOSE header, so an opaque
// token with coincidental dots is introspected like any other.
// Fail-on-old: an opaque token with exactly two dots is rejected (401),
// never introspected, when requireTokenIntrospection is set.
func TestR166_BearerOpaqueWithTwoDotsIntrospected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":     true,
			"sub":        "opaque-two-dots",
			"token_type": "Bearer",
		})
	}))
	defer ts.Close()

	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	oidc := makeBearerOIDC(t, next)
	oidc.requireTokenIntrospection = true
	oidc.introspectionURL = ts.URL
	oidc.httpClient = ts.Client()
	oidc.clientSecret = "secret"

	// Opaque token with exactly two dots, but its first segment is not a
	// decodable JOSE header (so it is not a JWT, only looks like one).
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer a.b.c")
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if !nextCalled.Load() {
		t.Fatalf("opaque token containing exactly two dots must be introspected and forwarded when requireTokenIntrospection is set; status=%d body=%q", rw.Code, rw.Body.String())
	}
}
