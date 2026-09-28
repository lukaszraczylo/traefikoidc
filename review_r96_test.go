package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// R96 regression: backchannel/front-channel logout must invalidate sessions in
// distributed (serializing-backend) deployments too. The Redis backend JSON
// round-trips the stored unix-second int64 as a float64, so the previous
// strict `val.(int64)` assertion always failed and isSessionInvalidated
// returned false — the user stayed authenticated after IdP-initiated logout
// whenever sessionInvalidationCache was backed by Redis.
func TestSessionInvalidationReadsFloat64FromSerializingBackend(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: &mockCacheInterface{data: map[string]interface{}{}},
	}
	sid, sub := "session-123", "subject-9"
	now := time.Now()
	cache := oidc.sessionInvalidationCache
	// Simulate the Redis round-trip: invalidateSession stores time.Now().Unix()
	// (int64), but the serializing backend returns float64 on Get.
	cache.Set(oidc.buildSessionInvalidationKey("sid", sid), float64(now.Unix()), time.Hour)

	// Session created before the invalidation must be considered invalid (by sid).
	if !oidc.isSessionInvalidated(sid, "", now.Add(-time.Minute)) {
		t.Fatalf("expected session to be invalidated when cache returns float64 (Redis)")
	}

	// By-subject invalidation must also work with the same float64 round-trip.
	cache.Set(oidc.buildSessionInvalidationKey("sub", sub), float64(now.Unix()), time.Hour)
	if !oidc.isSessionInvalidated("", sub, now.Add(-time.Minute)) {
		t.Fatalf("expected subject to be invalidated when cache returns float64 (Redis)")
	}
}

// sessionInvalidationTime must accept every representation a cache backend may
// return: raw int64 (in-memory), float64 (JSON round-trip), json.Number.
func TestSessionInvalidationTimeAcceptsAllBackendTypes(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name   string
		val    interface{}
		want   int64
		wantOK bool
	}{
		{"int64 (local backend)", now, now, true},
		{"float64 (redis round-trip)", float64(now), now, true},
		{"json.Number", json.Number("1234567890"), 1234567890, true},
		{"unsupported type", "not-a-timestamp", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sessionInvalidationTime(tc.val)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// R96 P2-1 regression: a JSON-null group claim must be treated as an empty
// list, not a hard error. Previously a null group claim made the extraction
// fail, and with allowedRolesAndGroups set a valid holder of an allowed role
// was 403'd before the gate could see that role.
func TestNullGroupClaimStillAllowsRoleAuth(t *testing.T) {
	oidc := &TraefikOidc{
		next:                  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:                NewLogger("error"),
		groupClaimName:        "groups",
		roleClaimName:         "roles",
		allowedRolesAndGroups: map[string]struct{}{"admin": {}},
		minimalHeaders:        false, // R173: minimal mode now drops X-User-Roles; keep default mode to test the sibling-interaction
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	// groups present but null (decodes to nil); the allowed value is in roles.
	p := &principal{Identifier: "u", Claims: map[string]interface{}{"sub": "s", "groups": nil, "roles": []string{"admin"}}}
	oidc.forwardAuthorized(rw, req, p)

	if rw.Code == http.StatusForbidden {
		t.Fatalf("null group claim caused a 403 despite an allowed role")
	}
	if got := req.Header.Get("X-User-Roles"); got != "admin" {
		t.Fatalf("expected X-User-Roles set to allowed role, got %q", got)
	}
}

// R96 P2-2 regression: a malformed claim in one signal (e.g. numeric
// groups) must not suppress the valid sibling signal's header. Previously a
// single bad claim set extractErr != nil, skipping BOTH header writes.
func TestMalformedGroupDoesNotDropValidRoleHeader(t *testing.T) {
	oidc := &TraefikOidc{
		next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:         NewLogger("error"),
		groupClaimName: "groups",
		roleClaimName:  "roles",
		minimalHeaders: false, // R173: minimal mode now drops X-User-Roles; keep default mode to test the sibling-interaction
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	// groups is malformed (numeric), roles is valid.
	p := &principal{Identifier: "u", Claims: map[string]interface{}{"sub": "s", "groups": float64(7), "roles": []string{"editor"}}}
	oidc.forwardAuthorized(rw, req, p)

	if got := req.Header.Get("X-User-Roles"); got != "editor" {
		t.Fatalf("malformed groups claim dropped the valid roles header: got %q", got)
	}
}

// R96 regression: the per-IP 429 must report the ACTUAL remaining penalty
// (time until the penalty box expires), not the full configured penalty.
// writeBearerError previously overwrote the real value with the full penalty.
func TestWriteBearerErrorReportsActualRetryAfter(t *testing.T) {
	oidc := &TraefikOidc{bearerFailurePenalty: 60 * time.Second}
	actual := 5 * time.Second
	err := newBearerError(bearerErrThrottled, "ip in penalty box")
	err.retryAfter = actual

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	oidc.writeBearerError(rw, req, err)

	if got := rw.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("want Retry-After to reflect actual remaining penalty (5), got %q", got)
	}
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rw.Code)
	}
}

// R96 regression: a ported r.Host must not defeat the subdomain-bounding
// safeguard that keeps the token-bearing session cookie scoped to the serving
// host. Previously host = "app.example.com:8080" made HasSuffix(host,
// ".example.com") false, so the cookie Domain fell back to the strict
// parent X-Forwarded-Host — scoping it to every sibling subdomain.
func TestEnhanceSessionSecurity_StripPortBeforeSubdomainBound(t *testing.T) {
	sm := createTestSessionManager(t)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com:8080/", nil)
	req.Host = "app.example.com:8080"
	req.Header.Set("X-Forwarded-Host", "example.com") // strict parent
	opts := sm.EnhanceSessionSecurity(nil, req)
	if opts.Domain != "app.example.com" {
		t.Fatalf("want Domain stayed bounded to serving host app.example.com, got %q", opts.Domain)
	}
}
