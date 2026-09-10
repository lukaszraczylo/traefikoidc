package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FIX-13 regression tests.
//
// R156 (8640451) treated ANY 400-499 status from the introspection endpoint
// as a definite statement that the presented token is bad. RFC 7662 s2.2
// says an inactive/unknown token gets a 200 response with active=false;
// s2.3 says a 401 means the protected resource's OWN client credentials
// were rejected. A 4xx from the endpoint therefore means plugin-side
// misconfiguration (e.g. a rotated client_secret) or throttling (429), not
// "this token is bad". Only a 200 response with active=false may reject
// the token; 401/403 must map to "introspection unavailable" and 408/429
// must be treated as transient, on both the bearer and session paths.

// introspectionStatusServer returns an httptest.Server that always responds
// with the given HTTP status and an empty body.
func introspectionStatusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
}

// --- Bearer path (introspectOnBearerPath: used after full JWT verification
// to re-check revocation) ---

func TestIntrospectionStatus_BearerPath_401MapsToUnavailable(t *testing.T) {
	ts := introspectionStatusServer(t, http.StatusUnauthorized)
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:           newNoOpLogger(),
		introspectionURL: ts.URL,
		httpClient:       ts.Client(),
		clientID:         "test-client",
		clientSecret:     "test-secret",
	}
	bErr := tObj.introspectOnBearerPath("tok")
	if bErr == nil {
		t.Fatal("expected rejection")
	}
	if bErr.kind != bearerErrIntrospectionUnavailable {
		t.Fatalf("a 401 from the introspection endpoint (our own credentials rejected) must map to bearerErrIntrospectionUnavailable, got kind=%v reason=%q", bErr.kind, bErr.reason)
	}
}

func TestIntrospectionStatus_BearerPath_429MapsToUnavailable(t *testing.T) {
	ts := introspectionStatusServer(t, http.StatusTooManyRequests)
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:           newNoOpLogger(),
		introspectionURL: ts.URL,
		httpClient:       ts.Client(),
		clientID:         "test-client",
		clientSecret:     "test-secret",
	}
	bErr := tObj.introspectOnBearerPath("tok")
	if bErr == nil {
		t.Fatal("expected rejection")
	}
	if bErr.kind != bearerErrIntrospectionUnavailable {
		t.Fatalf("a 429 (throttled) from the introspection endpoint must map to bearerErrIntrospectionUnavailable, got kind=%v reason=%q", bErr.kind, bErr.reason)
	}
}

func TestIntrospectionStatus_BearerPath_ActiveFalseStillRejectsToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
	}))
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:           newNoOpLogger(),
		introspectionURL: ts.URL,
		httpClient:       ts.Client(),
		clientID:         "test-client",
		clientSecret:     "test-secret",
	}
	bErr := tObj.introspectOnBearerPath("tok")
	if bErr == nil {
		t.Fatal("a 200 response with active=false must still reject the token")
	}
	if bErr.kind != bearerErrTokenInactive {
		t.Fatalf("a 200/active=false must map to bearerErrTokenInactive, got kind=%v reason=%q", bErr.kind, bErr.reason)
	}
}

// --- Bearer path opaque-token introspection (FIX-03's
// buildPrincipalFromOpaqueIntrospection) ---

func TestIntrospectionStatus_BearerOpaque_401MapsToUnavailable(t *testing.T) {
	ts := introspectionStatusServer(t, http.StatusUnauthorized)
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:            newNoOpLogger(),
		introspectionURL:  ts.URL,
		httpClient:        ts.Client(),
		clientID:          "test-client",
		clientSecret:      "test-secret",
		allowOpaqueTokens: true,
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-tok")
	if bErr == nil {
		t.Fatal("expected rejection")
	}
	if bErr.kind != bearerErrIntrospectionUnavailable {
		t.Fatalf("a 401 from the introspection endpoint must map to bearerErrIntrospectionUnavailable, got kind=%v reason=%q", bErr.kind, bErr.reason)
	}
}

// --- Session path (validateStandardTokensRS via validateOpaqueToken) ---

func TestIntrospectionStatus_SessionPath_401FallsThroughNoForcedRefresh(t *testing.T) {
	ts := introspectionStatusServer(t, http.StatusUnauthorized)
	defer ts.Close()

	const idToken = "dummy-but-cached-id-token"
	tc := NewTokenCache()
	tc.Set(idToken, map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}, time.Hour)

	verifier := NewUnifiedMockTokenVerifier()
	verifier.SetTokenValid(idToken, true)

	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionURL:          ts.URL,
		httpClient:                ts.Client(),
		allowOpaqueTokens:         true,
		requireTokenIntrospection: false,
		tokenCache:                tc,
		tokenVerifier:             verifier,
		clientID:                  "test-client",
		clientSecret:              "test-secret",
	}
	rs := &requestState{
		authenticated: true,
		accessToken:   "OpaqueNotARealJwt-1234567890",
		refreshToken:  "refresh-token-value",
		idToken:       idToken,
	}
	_, shouldRefresh, _ := tObj.validateStandardTokensRS(rs)
	if shouldRefresh {
		t.Error("a 401 from the introspection endpoint (our own credentials rejected) is not a verdict on the token; it must fall through to ID-token validation, not force a refresh")
	}
}

func TestIntrospectionStatus_SessionPath_429FallsThroughNoForcedRefresh(t *testing.T) {
	ts := introspectionStatusServer(t, http.StatusTooManyRequests)
	defer ts.Close()

	const idToken = "dummy-but-cached-id-token"
	tc := NewTokenCache()
	tc.Set(idToken, map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}, time.Hour)

	verifier := NewUnifiedMockTokenVerifier()
	verifier.SetTokenValid(idToken, true)

	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionURL:          ts.URL,
		httpClient:                ts.Client(),
		allowOpaqueTokens:         true,
		requireTokenIntrospection: false,
		tokenCache:                tc,
		tokenVerifier:             verifier,
		clientID:                  "test-client",
		clientSecret:              "test-secret",
	}
	rs := &requestState{
		authenticated: true,
		accessToken:   "OpaqueNotARealJwt-1234567890",
		refreshToken:  "refresh-token-value",
		idToken:       idToken,
	}
	_, shouldRefresh, _ := tObj.validateStandardTokensRS(rs)
	if shouldRefresh {
		t.Error("a 429 (throttled) from the introspection endpoint must be treated as transient, not force a refresh")
	}
}

func TestIntrospectionStatus_SessionPath_ActiveFalseStillForcesRefresh(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
	}))
	defer ts.Close()

	const idToken = "dummy-but-cached-id-token"
	tc := NewTokenCache()
	tc.Set(idToken, map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}, time.Hour)

	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionURL:          ts.URL,
		httpClient:                ts.Client(),
		allowOpaqueTokens:         true,
		requireTokenIntrospection: false,
		tokenCache:                tc,
		clientID:                  "test-client",
		clientSecret:              "test-secret",
	}
	rs := &requestState{
		authenticated: true,
		accessToken:   "OpaqueNotARealJwt-1234567890",
		refreshToken:  "refresh-token-value",
		idToken:       idToken,
	}
	_, shouldRefresh, _ := tObj.validateStandardTokensRS(rs)
	if !shouldRefresh {
		t.Error("a 200 response with active=false is a definite revocation and must still force a refresh")
	}
}
