package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// issue154_regression_test.go — regression tests for issue #154.
//
// A providerURL pointing at a localhost identity provider (local
// development, sidecar OIDC providers) caused an infinite redirect loop.
// validateHost unconditionally rejected loopback/localhost hosts, so
// buildURLWithParams returned "" for the discovered authorization endpoint,
// buildAuthURL returned "", and Traefik kept redirecting to an empty
// Location header forever.
//
// The fix adds an unexported `allowLoopbackHosts bool` field to TraefikOidc,
// derived at construction time from `isLoopbackProviderURL(config.ProviderURL)`
// (settings.go). validateHost now gates loopback IPs and localhost/127.x/::1
// literals on `!t.allowLoopbackHosts`, while link-local, multicast, and the
// cloud-metadata hostnames stay unconditionally blocked (SSRF surface must
// not widen). updateMetadataEndpoints recomputes the same derivation from
// t.providerURL directly (not the struct field), so it stays correct for
// TraefikOidc values test code builds as struct literals.
//
// These tests pin: the opt-in behaves correctly, the default (flag unset)
// still blocks loopback exactly as before the fix, the SSRF-relevant hosts
// stay blocked even with the opt-in active, allowPrivateIPAddresses remains
// an independent gate, the derivation helper is correct in isolation, the
// end-to-end buildAuthURL behavior for both flag states, that NewWithContext
// derives the field correctly from config.ProviderURL, and that the
// discovery layer (updateMetadataEndpoints) and the URL-validation layer
// (validateHost/buildAuthURL) agree on a loopback provider.

// issue154LoopbackHosts are host strings that represent localhost/loopback
// under every literal form validateHost must recognize: bare hostname,
// hostname:port, case variation, IPv4 loopback with and without port, an
// IPv6 loopback literal with port, and a non-canonical loopback IP
// (127.0.0.0/8 is entirely loopback, not just 127.0.0.1).
var issue154LoopbackHosts = []string{
	"localhost",
	"localhost:8080",
	"LOCALHOST",
	"127.0.0.1",
	"127.0.0.1:8080",
	"[::1]:8080",
	"127.0.0.2:9000",
}

// TestIssue154ValidateHostLoopbackAllowed pins the opt-in: once a middleware
// instance has allowLoopbackHosts=true (as New/NewWithContext derive it from
// a loopback providerURL), every loopback host form validates cleanly.
func TestIssue154ValidateHostLoopbackAllowed(t *testing.T) {
	middleware := createMinimalMiddleware()
	middleware.allowLoopbackHosts = true

	for _, host := range issue154LoopbackHosts {
		t.Run(host, func(t *testing.T) {
			if err := middleware.validateHost(host); err != nil {
				t.Fatalf("validateHost(%q) with allowLoopbackHosts=true must succeed, got: %v", host, err)
			}
		})
	}
}

// TestIssue154ValidateHostLoopbackDefaultBlocked pins the default-preserving
// half of the fix: a middleware instance built without explicitly setting
// allowLoopbackHosts (its zero value, matching every TraefikOidc a
// non-loopback New()/NewWithContext call produces) must still reject every
// loopback host form, exactly as before the fix. This is asserted as
// "error present", not against exact error text: "[::1]:8080" alone
// (without a bracket-less counterpart) does not hit the pre-existing
// net.SplitHostPort quirk where a bare "[::1]" without a port fails with
// "invalid host format" instead of the loopback-specific message — but
// pinning only non-nil keeps this test robust to either error path.
func TestIssue154ValidateHostLoopbackDefaultBlocked(t *testing.T) {
	middleware := createMinimalMiddleware() // allowLoopbackHosts left at zero value (false)

	for _, host := range issue154LoopbackHosts {
		t.Run(host, func(t *testing.T) {
			if err := middleware.validateHost(host); err == nil {
				t.Fatalf("validateHost(%q) with default allowLoopbackHosts must still be rejected", host)
			}
		})
	}
}

// TestIssue154SecurityEnvelopeWithLoopbackAllowed is the highest-value test
// in this file: it proves that opting into loopback hosts does not widen the
// SSRF surface. Cloud metadata addresses, link-local, multicast, and
// unspecified addresses must stay blocked even with allowLoopbackHosts=true.
func TestIssue154SecurityEnvelopeWithLoopbackAllowed(t *testing.T) {
	middleware := createMinimalMiddleware()
	middleware.allowLoopbackHosts = true

	cases := []struct {
		name       string
		host       string
		wantSubstr string
	}{
		{"AWS/GCP metadata IP", "169.254.169.254", "loopback/link-local"},
		{"AWS/GCP metadata IP with port", "169.254.169.254:80", "loopback/link-local"},
		{"GCP metadata hostname", "metadata.google.internal", "dangerous hostname"},
		{"GCP metadata hostname with port", "metadata.google.internal:80", "dangerous hostname"},
		{"IPv6 link-local", "[fe80::1]:80", "loopback/link-local"},
		{"IPv4 link-local multicast", "224.0.0.1", "loopback/link-local"},
		{"unspecified IPv4", "0.0.0.0", "unspecified or multicast"},
		{"unspecified IPv6 with port", "[::]:80", "unspecified or multicast"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := middleware.validateHost(tc.host)
			if err == nil {
				t.Fatalf("validateHost(%q) must still be rejected with allowLoopbackHosts=true", tc.host)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("validateHost(%q) error = %q, want substring %q", tc.host, err.Error(), tc.wantSubstr)
			}
		})
	}
}

// TestIssue154PrivateIPIndependence proves allowLoopbackHosts and
// allowPrivateIPAddresses are independent gates: opting a middleware into
// loopback hosts must not also open up RFC 1918 private ranges.
func TestIssue154PrivateIPIndependence(t *testing.T) {
	middleware := createMinimalMiddleware()
	middleware.allowLoopbackHosts = true
	middleware.allowPrivateIPAddresses = false

	privateHosts := []string{"10.0.0.5", "192.168.1.10", "172.16.0.1"}
	for _, host := range privateHosts {
		t.Run(host, func(t *testing.T) {
			err := middleware.validateHost(host)
			if err == nil {
				t.Fatalf("validateHost(%q) must be rejected when allowPrivateIPAddresses=false", host)
			}
			if !strings.Contains(err.Error(), "private/internal") {
				t.Fatalf("validateHost(%q) error = %q, want substring %q", host, err.Error(), "private/internal")
			}
		})
	}
}

// TestIssue154IsLoopbackProviderURL exercises the construction-time
// derivation helper in isolation, including malformed input that must not
// panic.
func TestIssue154IsLoopbackProviderURL(t *testing.T) {
	cases := []struct {
		name        string
		providerURL string
		want        bool
	}{
		{"http localhost with port", "http://localhost:8080", true},
		{"http loopback IPv4 with port", "http://127.0.0.1:9000", true},
		{"http loopback IPv6 with port", "http://[::1]:9000", true},
		{"https localhost uppercase", "https://LOCALHOST:9000", true},
		{"https real remote provider", "https://accounts.google.com", false},
		{"https another remote provider", "https://idp.example.com", false},
		{"empty string", "", false},
		{"malformed URL must not panic", "://garbage", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLoopbackProviderURL(tc.providerURL)
			if got != tc.want {
				t.Fatalf("isLoopbackProviderURL(%q) = %v, want %v", tc.providerURL, got, tc.want)
			}
		})
	}
}

// TestIssue154BuildAuthURLLoopbackProvider is the issue scenario reproduced
// at the unit level: a loopback authURL must produce a real redirect URL
// when allowLoopbackHosts is set, and the pre-fix behavior (empty string,
// the infinite-redirect-loop trigger) must be pinned as the default when it
// is not.
func TestIssue154BuildAuthURLLoopbackProvider(t *testing.T) {
	t.Run("allowLoopbackHosts=true builds a real auth URL", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.allowLoopbackHosts = true
		middleware.authURL = "http://localhost:8080/oauth/authorize"
		middleware.issuerURL = "http://localhost:8080"

		got := middleware.buildAuthURL("http://localhost:5555/callback", "state123", "nonce456", "")

		if got == "" {
			t.Fatal("buildAuthURL returned empty string for a loopback provider with allowLoopbackHosts=true")
		}
		if !strings.HasPrefix(got, "http://localhost:8080/oauth/authorize?") {
			t.Fatalf("buildAuthURL = %q, want prefix %q", got, "http://localhost:8080/oauth/authorize?")
		}
		for _, want := range []string{"client_id=", "state=state123", "nonce=nonce456"} {
			if !strings.Contains(got, want) {
				t.Fatalf("buildAuthURL = %q, want it to contain %q", got, want)
			}
		}
	})

	t.Run("default allowLoopbackHosts=false pins pre-fix empty-string behavior", func(t *testing.T) {
		middleware := createMinimalMiddleware() // allowLoopbackHosts left at zero value (false)
		middleware.authURL = "http://localhost:8080/oauth/authorize"
		middleware.issuerURL = "http://localhost:8080"

		got := middleware.buildAuthURL("http://localhost:5555/callback", "state123", "nonce456", "")

		if got != "" {
			t.Fatalf("buildAuthURL = %q, want empty string when a loopback provider is not opted in", got)
		}
	})
}

// issue154BaseConfig returns a complete, valid Config with the given
// providerURL, following the minimal-valid-config pattern used elsewhere in
// this package (e.g. TestRank2And6_InvalidConfigFailsClosed in
// security_audit_fixes_test.go).
func issue154BaseConfig(providerURL string) *Config {
	return &Config{
		ProviderURL:          providerURL,
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
		RateLimit:            100,
	}
}

// TestIssue154NewWithContextDerivation proves NewWithContext derives
// allowLoopbackHosts from config.ProviderURL at construction time (main.go,
// the `allowLoopbackHosts: isLoopbackProviderURL(config.ProviderURL)` field
// initializer). The field is set synchronously before the metadata-discovery
// goroutine starts, so this needs no live discovery endpoint: the ports used
// below (a loopback port nothing listens on, and an RFC 2606 .invalid host)
// only need to fail fast once the background goroutine attempts discovery —
// Close() cancels that goroutine's context regardless of outcome.
func TestIssue154NewWithContextDerivation(t *testing.T) {
	t.Run("loopback providerURL derives allowLoopbackHosts=true", func(t *testing.T) {
		// A real httptest server (loopback by construction) so the
		// background discovery goroutine NewWithContext starts completes
		// quickly and Close() below does not have to wait out its 10s
		// goroutine-shutdown timeout for an unreachable host. Mirrors
		// TestInitializeMetadata's server setup in main_initialization_test.go.
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   srv.URL,
					AuthURL:  srv.URL + "/auth",
					TokenURL: srv.URL + "/token",
					JWKSURL:  srv.URL + "/jwks",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		cfg := issue154BaseConfig(srv.URL)
		oidc, err := NewWithContext(context.Background(), cfg, nil, "issue154-loopback")
		if err != nil {
			t.Fatalf("NewWithContext must accept a valid loopback config, got: %v", err)
		}
		defer func() { _ = oidc.Close() }()

		if !oidc.allowLoopbackHosts {
			t.Fatal("expected allowLoopbackHosts=true for a loopback providerURL")
		}
	})

	t.Run("non-loopback providerURL derives allowLoopbackHosts=false", func(t *testing.T) {
		cfg := issue154BaseConfig("https://provider.invalid")
		oidc, err := NewWithContext(context.Background(), cfg, nil, "issue154-remote")
		if err != nil {
			t.Fatalf("NewWithContext must accept a valid remote config, got: %v", err)
		}
		defer func() { _ = oidc.Close() }()

		if oidc.allowLoopbackHosts {
			t.Fatal("expected allowLoopbackHosts=false for a non-loopback providerURL")
		}
	})
}

// TestIssue154DiscoveryAndURLValidationAgree catches layer drift between the
// discovery-endpoint sanitizer (updateMetadataEndpoints, which recomputes
// isLoopbackProviderURL(t.providerURL) itself per its doc comment, since
// test helpers build &TraefikOidc{} literals without going through
// NewWithContext) and the outbound URL validator (validateHost, gated on the
// allowLoopbackHosts field). Both layers must agree that a loopback provider
// is usable end-to-end: discovery must accept the loopback authURL, and
// buildAuthURL must build a real URL once allowLoopbackHosts is set to
// mirror what NewWithContext would have derived.
func TestIssue154DiscoveryAndURLValidationAgree(t *testing.T) {
	oidc := &TraefikOidc{
		providerURL: "http://localhost:8080",
		logger:      NewLogger("debug"),
		clientID:    "test-client",
	}

	metadata := &ProviderMetadata{
		Issuer:   "http://localhost:8080",
		AuthURL:  "http://localhost:8080/oauth/authorize",
		TokenURL: "http://localhost:8080/oauth/token",
		JWKSURL:  "http://localhost:8080/jwks",
	}
	oidc.updateMetadataEndpoints(metadata)

	if oidc.authURL == "" {
		t.Fatal("updateMetadataEndpoints rejected a loopback authURL for a loopback providerURL (discovery layer drift)")
	}

	// The URL-validation layer must independently agree once
	// allowLoopbackHosts mirrors what NewWithContext would have derived from
	// this same loopback providerURL.
	oidc.allowLoopbackHosts = true
	if got := oidc.buildAuthURL("http://localhost:5555/callback", "state", "nonce", ""); got == "" {
		t.Fatal("buildAuthURL returned empty for the discovered loopback authURL with allowLoopbackHosts=true (validation layer drift)")
	}
}
