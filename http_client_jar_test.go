package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPooledTokenClient_DoesNotShareCookieJarAcrossRequests regresses
// FIX-12: R70 gave CreatePooledHTTPClient's client a cookie jar whenever
// UseCookieJar is set, and TokenHTTPClientConfig (used to build the single
// per-plugin-instance tokenHTTPClient, main.go) set UseCookieJar: true. That
// one client, and its one jar, is shared by every user's token/refresh
// exchange. An IdP Set-Cookie on user A's exchange was stored in the shared
// jar and replayed on user B's next token request to the same host -
// cross-user state confusion at the IdP. Token/refresh calls are stateless
// back-channel requests and must never carry a cross-request jar.
func TestPooledTokenClient_DoesNotShareCookieJarAcrossRequests(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			// Simulate the IdP setting a session/affinity cookie on user A's
			// token exchange response.
			http.SetCookie(w, &http.Cookie{Name: "idp_sess", Value: "alice"})
			w.WriteHeader(http.StatusOK)
			return
		}
		// User B's request: must not carry the cookie set on user A's call.
		if c, err := r.Cookie("idp_sess"); err == nil {
			t.Errorf("request %d carried leaked cookie idp_sess=%s from an earlier request", requests, c.Value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := CreatePooledHTTPClient(TokenHTTPClientConfig())

	// Request 1 (user A): receives and would store the IdP's Set-Cookie if
	// the client has a jar.
	resp1, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	resp1.Body.Close()

	// Request 2 (user B, same pooled client, same host): must be a clean
	// request with no cookie carried over from request 1.
	resp2, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	resp2.Body.Close()

	if requests != 2 {
		t.Fatalf("want 2 requests reaching the server, got %d", requests)
	}
}
