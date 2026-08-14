package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestBuildURLWithParams_PreservesEndpointQuery regresses buildURLWithParams
// overwriting (RawQuery = params.Encode()) and thus dropping any query
// string already present on a discovered endpoint URL. Some IdPs embed
// client_id or template params in their authorization/end-session
// endpoints; dropping them produced an invalid authorize/logout request.
// Authoritative plugin params (client_id, redirect_uri, state, ...) still
// take precedence over the preserved base query.
func TestBuildURLWithParams_PreservesEndpointQuery(t *testing.T) {
	oidc := &TraefikOidc{logger: NewLogger("debug")}

	params := url.Values{}
	params.Set("client_id", "my-client")
	params.Set("redirect_uri", "https://app.example.com/callback")

	got := oidc.buildURLWithParams("https://api.example.com/authorize?provider=zanzibar&client_id=embedded", params)

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}
	q := u.Query()

	if q.Get("provider") != "zanzibar" {
		t.Fatalf("pre-existing endpoint query param 'provider' was dropped; result %q", got)
	}
	if q.Get("client_id") != "my-client" {
		t.Fatalf("authoritative client_id must win over embedded one; got %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Fatalf("authoritative redirect_uri missing; got %q", q.Get("redirect_uri"))
	}
}

// TestSessionClear_ExpiresCookies regresses Clear() discarding its MaxAge=-1
// expiry on the combined-storage path. Previously Clear cleared the values
// but its subsequent Save() rebuilt options with a positive sessionMaxAge,
// so the browser was left an EMPTY merged session cookie with a fresh
// Max-Age that lingered for the full session lifetime after logout,
// instead of an expired one.
func TestSessionClear_ExpiresCookies(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters-long", false, "", "", time.Hour, NewLogger("debug"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	// Write an authenticated session so Clear has a real cookie to expire.
	req1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw1 := httptest.NewRecorder()
	sd1, err := sm.GetSession(req1)
	if err != nil {
		t.Fatalf("GetSession(write): %v", err)
	}
	_ = sd1.SetAuthenticated(true)
	sd1.SetUserIdentifier("user@example.com")
	sd1.SetAccessToken("some-access-token")
	if err := sd1.Save(req1, rw1); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload the session from the written cookies.
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range rw1.Result().Cookies() {
		req2.AddCookie(c)
	}
	sd2, err := sm.GetSession(req2)
	if err != nil {
		t.Fatalf("GetSession(reload): %v", err)
	}
	if !sd2.GetAuthenticated() {
		t.Fatal("expected session to reload as authenticated")
	}

	// Force the combined-storage path — the one where Clear historically
	// re-issued a fresh positive Max-Age instead of expiring the cookie.
	sd2.useCombinedStorage = true

	rw2 := httptest.NewRecorder()
	if err := sd2.Clear(req2, rw2); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	combinedName := sm.combinedChunkCookieName(0)
	now := time.Now()
	var clearCookies []string
	for _, c := range rw2.Result().Cookies() {
		clearCookies = append(clearCookies, c.String())
		if c.Name != combinedName {
			continue
		}
		if (c.MaxAge != 0 && c.MaxAge <= 0) || (!c.Expires.IsZero() && c.Expires.Before(now)) {
			return // combined chunk is properly expired
		}
	}
	t.Fatalf("combined chunk cookie %q not expired after Clear; Set-Cookie set: %v", combinedName, clearCookies)
}

// TestSendErrorResponse_NoStore regresses sendErrorResponse leaving auth
// error responses cacheable. Every /login and /callback failure (401/403/
// 429/503) goes through it; without Cache-Control a browser or shared
// intermediary could serve a stale 401/403 body after a subsequent
// successful authentication. Both the JSON and HTML branches must carry
// no-store.
func TestSendErrorResponse_NoStore(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		wantCT string
	}{
		{name: "json", accept: "application/json", wantCT: "application/json"},
		{name: "html", accept: "text/html", wantCT: "text/html"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oidc := &TraefikOidc{logger: NewLogger("debug")}
			req := httptest.NewRequest(http.MethodGet, "/cb", nil)
			req.Header.Set("Accept", tc.accept)
			rw := httptest.NewRecorder()
			oidc.sendErrorResponse(rw, req, "boom", http.StatusUnauthorized)

			if got := rw.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			if rw.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rw.Code, http.StatusUnauthorized)
			}
		})
	}
}
