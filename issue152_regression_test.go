package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// issue152_regression_test.go — regression tests for issue #152.
//
// Three provider endpoints — token revocation, OIDC end-session (logout), and
// RFC 7662 token introspection — were documented Config fields
// (RevocationURL, OIDCEndSessionURL) or a brand-new one (IntrospectionURL)
// that operators can set when their IdP omits an endpoint from discovery, or
// to pin a non-standard one. RevocationURL and OIDCEndSessionURL were dead:
// Config.Validate() checked them but nothing ever copied them onto the live
// TraefikOidc fields consumers read, so setting them silently did nothing.
// IntrospectionURL did not exist at all.
//
// The fix adds three unexported write-once fields on TraefikOidc
// (configRevocationURL, configEndSessionURL, configIntrospectionURL),
// populated from Config at construction (main.go NewWithContext). The same
// three values also cold-start-seed the live fields (revocationURL,
// endSessionURL, introspectionURL) so a discovery failure does not lose an
// operator override. Inside updateMetadataEndpoints, after the SSRF sanitize
// pass, the introspection same-host pin, and the issuer pin — but before the
// metadataMu.Lock() that publishes the live fields — each non-empty config*
// field overwrites the corresponding metadata.* value, so a manual override
// wins over discovery on every refresh, not just at construction. An empty
// override leaves the discovered value alone. Manual overrides deliberately
// skip validateDiscoveredEndpoint and the introspection same-host pin: they
// sit at the same trust tier as providerURL itself, already gated by
// isValidSecureURL at config-validation time.
//
// These tests pin: default (no overrides) behavior is unchanged, overrides
// win over both absent and present discovered values, a cross-host
// introspection override survives the same-host pin that a discovered
// cross-host endpoint does not, overrides survive repeated metadata
// refreshes, NewWithContext wires the three config* fields and cold-start
// seeds correctly (including when discovery fails outright), the override
// is honored end-to-end by introspectToken and RevokeTokenWithProvider, the
// logout URL builder emits the override, and Config.Validate / New enforce
// the same "invalid configuration" + untyped-nil-handler contract (#151)
// for a bad IntrospectionURL that the sibling fields already had.

// issue152BaseConfig returns a complete, valid Config, following the
// minimal-valid-config pattern used elsewhere in this package (e.g.
// issue154BaseConfig in issue154_regression_test.go).
func issue152BaseConfig() *Config {
	return &Config{
		ProviderURL:          "https://provider.example.com",
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
		RateLimit:            100,
	}
}

// issue152Endpoints reads the three metadataMu-guarded live endpoint fields
// under lock, so callers stay race-clean regardless of whether a background
// discovery goroutine may still touch them.
func issue152Endpoints(oidc *TraefikOidc) (revocation, endSession, introspection string) {
	oidc.metadataMu.RLock()
	defer oidc.metadataMu.RUnlock()
	return oidc.revocationURL, oidc.endSessionURL, oidc.introspectionURL
}

// TestIssue152DefaultPreservation proves the fix is additive: with no
// operator overrides, updateMetadataEndpoints behaves exactly as before —
// discovered values become the live fields and the published snapshot.
func TestIssue152DefaultPreservation(t *testing.T) {
	t.Run("discovered values populate live fields and snapshot", func(t *testing.T) {
		oidc := &TraefikOidc{
			providerURL: "https://provider.example.com",
			logger:      NewLogger("error"),
			clientID:    "test-client",
		}
		metadata := &ProviderMetadata{
			Issuer:           "https://provider.example.com",
			AuthURL:          "https://provider.example.com/authorize",
			TokenURL:         "https://provider.example.com/token",
			JWKSURL:          "https://provider.example.com/jwks",
			RevokeURL:        "https://provider.example.com/revoke",
			EndSessionURL:    "https://provider.example.com/endsession",
			IntrospectionURL: "https://provider.example.com/introspect",
			RegistrationURL:  "https://provider.example.com/register",
		}

		oidc.updateMetadataEndpoints(metadata)

		revocation, endSession, introspection := issue152Endpoints(oidc)
		if revocation != metadata.RevokeURL {
			t.Fatalf("revocationURL = %q, want discovered %q", revocation, metadata.RevokeURL)
		}
		if endSession != metadata.EndSessionURL {
			t.Fatalf("endSessionURL = %q, want discovered %q", endSession, metadata.EndSessionURL)
		}
		if introspection != metadata.IntrospectionURL {
			t.Fatalf("introspectionURL = %q, want discovered %q", introspection, metadata.IntrospectionURL)
		}

		snap := oidc.metadataSnap()
		if snap == nil {
			t.Fatal("metadataSnap() returned nil after updateMetadataEndpoints")
		}
		if snap.RevocationURL != metadata.RevokeURL || snap.EndSessionURL != metadata.EndSessionURL || snap.IntrospectionURL != metadata.IntrospectionURL {
			t.Fatalf("metadataSnapshot = %+v, want it to match discovered metadata %+v", snap, metadata)
		}
	})

	t.Run("discovery omits introspection and no override leaves it empty", func(t *testing.T) {
		oidc := &TraefikOidc{
			providerURL: "https://provider.example.com",
			logger:      NewLogger("error"),
			clientID:    "test-client",
		}
		metadata := &ProviderMetadata{
			Issuer:   "https://provider.example.com",
			AuthURL:  "https://provider.example.com/authorize",
			TokenURL: "https://provider.example.com/token",
			JWKSURL:  "https://provider.example.com/jwks",
			// IntrospectionURL intentionally omitted.
		}

		oidc.updateMetadataEndpoints(metadata)

		_, _, introspection := issue152Endpoints(oidc)
		if introspection != "" {
			t.Fatalf("introspectionURL = %q, want empty when discovery omits it and no override is set", introspection)
		}
	})
}

// TestIssue152OverridesWin proves a non-empty config* override always wins
// over discovery, whether discovery is silent on the endpoint (a) or
// actively supplies a different value (b), and that a cross-host
// introspection override survives the same-host pin that a discovered
// cross-host introspection endpoint does not (c).
func TestIssue152OverridesWin(t *testing.T) {
	overrideRevocation := "https://override.example.com/revoke"
	overrideEndSession := "https://override.example.com/endsession"
	overrideIntrospection := "https://override.example.com/introspect"

	newOverriddenOidc := func() *TraefikOidc {
		return &TraefikOidc{
			providerURL:            "https://provider.example.com",
			logger:                 NewLogger("error"),
			clientID:               "test-client",
			configRevocationURL:    overrideRevocation,
			configEndSessionURL:    overrideEndSession,
			configIntrospectionURL: overrideIntrospection,
		}
	}

	t.Run("discovery omits endpoints, overrides fill them in", func(t *testing.T) {
		oidc := newOverriddenOidc()
		metadata := &ProviderMetadata{
			Issuer:   "https://provider.example.com",
			AuthURL:  "https://provider.example.com/authorize",
			TokenURL: "https://provider.example.com/token",
			JWKSURL:  "https://provider.example.com/jwks",
		}

		oidc.updateMetadataEndpoints(metadata)

		revocation, endSession, introspection := issue152Endpoints(oidc)
		if revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
			t.Fatalf("got (%q, %q, %q), want overrides (%q, %q, %q)",
				revocation, endSession, introspection, overrideRevocation, overrideEndSession, overrideIntrospection)
		}
		snap := oidc.metadataSnap()
		if snap == nil || snap.RevocationURL != overrideRevocation || snap.EndSessionURL != overrideEndSession || snap.IntrospectionURL != overrideIntrospection {
			t.Fatalf("metadataSnapshot = %+v, want overrides", snap)
		}
	})

	t.Run("discovery supplies different values, overrides win anyway", func(t *testing.T) {
		oidc := newOverriddenOidc()
		metadata := &ProviderMetadata{
			Issuer:           "https://provider.example.com",
			AuthURL:          "https://provider.example.com/authorize",
			TokenURL:         "https://provider.example.com/token",
			JWKSURL:          "https://provider.example.com/jwks",
			RevokeURL:        "https://provider.example.com/discovered-revoke",
			EndSessionURL:    "https://provider.example.com/discovered-endsession",
			IntrospectionURL: "https://provider.example.com/discovered-introspect",
		}

		oidc.updateMetadataEndpoints(metadata)

		revocation, endSession, introspection := issue152Endpoints(oidc)
		if revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
			t.Fatalf("got (%q, %q, %q), want overrides (%q, %q, %q) to beat discovered values",
				revocation, endSession, introspection, overrideRevocation, overrideEndSession, overrideIntrospection)
		}
	})

	t.Run("cross-host introspection: discovered is zeroed, override survives", func(t *testing.T) {
		// No override: a discovered introspection endpoint on a different host
		// than providerURL must be zeroed by the same-host pin.
		oidc := &TraefikOidc{
			providerURL: "https://provider.example.com",
			logger:      NewLogger("error"),
			clientID:    "test-client",
		}
		metadata := &ProviderMetadata{
			Issuer:           "https://provider.example.com",
			AuthURL:          "https://provider.example.com/authorize",
			TokenURL:         "https://provider.example.com/token",
			JWKSURL:          "https://provider.example.com/jwks",
			IntrospectionURL: "https://attacker.example.com/introspect",
		}
		oidc.updateMetadataEndpoints(metadata)
		if _, _, introspection := issue152Endpoints(oidc); introspection != "" {
			t.Fatalf("introspectionURL = %q, want empty: discovered cross-host introspection must be zeroed by the same-host pin", introspection)
		}

		// Same cross-host discovered value, but now with a cross-host override:
		// the override must survive because it skips the same-host pin.
		oidcWithOverride := &TraefikOidc{
			providerURL:            "https://provider.example.com",
			logger:                 NewLogger("error"),
			clientID:               "test-client",
			configIntrospectionURL: overrideIntrospection,
		}
		oidcWithOverride.updateMetadataEndpoints(metadata)
		if _, _, introspection := issue152Endpoints(oidcWithOverride); introspection != overrideIntrospection {
			t.Fatalf("introspectionURL = %q, want override %q to survive despite being cross-host", introspection, overrideIntrospection)
		}
	})
}

// TestIssue152RefreshSurvival proves overrides are re-applied inside
// updateMetadataEndpoints itself, so they survive every metadata refresh —
// not just the first call after construction.
func TestIssue152RefreshSurvival(t *testing.T) {
	overrideRevocation := "https://override.example.com/revoke"
	overrideEndSession := "https://override.example.com/endsession"
	overrideIntrospection := "https://override.example.com/introspect"

	oidc := &TraefikOidc{
		providerURL:            "https://provider.example.com",
		logger:                 NewLogger("error"),
		clientID:               "test-client",
		configRevocationURL:    overrideRevocation,
		configEndSessionURL:    overrideEndSession,
		configIntrospectionURL: overrideIntrospection,
	}

	firstRefresh := &ProviderMetadata{
		Issuer:           "https://provider.example.com",
		AuthURL:          "https://provider.example.com/authorize",
		TokenURL:         "https://provider.example.com/token",
		JWKSURL:          "https://provider.example.com/jwks",
		RevokeURL:        "https://provider.example.com/refresh1-revoke",
		EndSessionURL:    "https://provider.example.com/refresh1-endsession",
		IntrospectionURL: "https://provider.example.com/refresh1-introspect",
	}
	oidc.updateMetadataEndpoints(firstRefresh)
	if revocation, endSession, introspection := issue152Endpoints(oidc); revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
		t.Fatalf("after 1st refresh: got (%q, %q, %q), want overrides to hold", revocation, endSession, introspection)
	}

	secondRefresh := &ProviderMetadata{
		Issuer:           "https://provider.example.com",
		AuthURL:          "https://provider.example.com/authorize",
		TokenURL:         "https://provider.example.com/token",
		JWKSURL:          "https://provider.example.com/jwks",
		RevokeURL:        "https://provider.example.com/refresh2-revoke",
		EndSessionURL:    "https://provider.example.com/refresh2-endsession",
		IntrospectionURL: "https://provider.example.com/refresh2-introspect",
	}
	oidc.updateMetadataEndpoints(secondRefresh)
	if revocation, endSession, introspection := issue152Endpoints(oidc); revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
		t.Fatalf("after 2nd refresh: got (%q, %q, %q), want overrides to still hold", revocation, endSession, introspection)
	}
}

// TestIssue152NewWithContextWiring proves NewWithContext wires
// Config.RevocationURL / OIDCEndSessionURL / IntrospectionURL onto the three
// unexported config* fields and cold-start-seeds the live fields from them
// (main.go, the configRevocationURL/configEndSessionURL/configIntrospectionURL
// and revocationURL/endSessionURL/introspectionURL initializers), both when
// discovery succeeds with different values (override must still win) and
// when discovery fails outright (the cold-start seed must not be lost).
func TestIssue152NewWithContextWiring(t *testing.T) {
	overrideRevocation := "https://override.example.com/revoke"
	overrideEndSession := "https://override.example.com/endsession"
	overrideIntrospection := "https://override.example.com/introspect"

	t.Run("discovery succeeds with different values, overrides still win", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:           srv.URL,
					AuthURL:          srv.URL + "/auth",
					TokenURL:         srv.URL + "/token",
					JWKSURL:          srv.URL + "/jwks",
					RevokeURL:        srv.URL + "/discovered-revoke",
					EndSessionURL:    srv.URL + "/discovered-endsession",
					IntrospectionURL: srv.URL + "/discovered-introspect",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		cfg := issue152BaseConfig()
		cfg.ProviderURL = srv.URL
		cfg.RevocationURL = overrideRevocation
		cfg.OIDCEndSessionURL = overrideEndSession
		cfg.IntrospectionURL = overrideIntrospection

		oidc, err := NewWithContext(context.Background(), cfg, nil, "issue152-wiring-success")
		if err != nil {
			t.Fatalf("NewWithContext must accept a valid config with overrides, got: %v", err)
		}
		defer func() { _ = oidc.Close() }()

		<-oidc.initComplete // wait for the discovery goroutine so field reads below are race-safe.

		revocation, endSession, introspection := issue152Endpoints(oidc)
		if revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
			t.Fatalf("got (%q, %q, %q), want overrides (%q, %q, %q) to win over successful discovery",
				revocation, endSession, introspection, overrideRevocation, overrideEndSession, overrideIntrospection)
		}
	})

	t.Run("discovery fails outright, cold-start seed holds", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		cfg := issue152BaseConfig()
		cfg.ProviderURL = srv.URL
		cfg.RevocationURL = overrideRevocation
		cfg.OIDCEndSessionURL = overrideEndSession
		cfg.IntrospectionURL = overrideIntrospection

		oidc, err := NewWithContext(context.Background(), cfg, nil, "issue152-wiring-coldstart")
		if err != nil {
			t.Fatalf("NewWithContext must accept a valid config even though discovery will fail, got: %v", err)
		}
		defer func() { _ = oidc.Close() }()

		<-oidc.initComplete // discovery has failed and returned by now.

		revocation, endSession, introspection := issue152Endpoints(oidc)
		if revocation != overrideRevocation || endSession != overrideEndSession || introspection != overrideIntrospection {
			t.Fatalf("got (%q, %q, %q), want the constructor's cold-start seed (%q, %q, %q) to survive a failed discovery",
				revocation, endSession, introspection, overrideRevocation, overrideEndSession, overrideIntrospection)
		}
	})
}

// TestIssue152EndToEndIntrospection proves the override is honored one layer
// up from the field: with a discovery document that omits
// introspection_endpoint entirely, introspectToken (token_introspection.go)
// must still reach the manually-configured endpoint and return its result.
func TestIssue152EndToEndIntrospection(t *testing.T) {
	var hits int32
	var gotToken string
	introspectionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if err := r.ParseForm(); err == nil {
			gotToken = r.PostFormValue("token")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
	}))
	defer introspectionSrv.Close()

	oidc := &TraefikOidc{
		providerURL:            "https://provider.example.com",
		logger:                 NewLogger("error"),
		clientID:               "test-client",
		clientSecret:           "test-secret",
		httpClient:             http.DefaultClient,
		configIntrospectionURL: introspectionSrv.URL,
	}
	metadata := &ProviderMetadata{
		Issuer:   "https://provider.example.com",
		AuthURL:  "https://provider.example.com/authorize",
		TokenURL: "https://provider.example.com/token",
		JWKSURL:  "https://provider.example.com/jwks",
		// IntrospectionURL intentionally omitted: the override is the only
		// source of the endpoint.
	}
	oidc.updateMetadataEndpoints(metadata)

	if _, _, introspection := issue152Endpoints(oidc); introspection != introspectionSrv.URL {
		t.Fatalf("introspectionURL = %q, want override %q wired before calling introspectToken", introspection, introspectionSrv.URL)
	}

	resp, err := oidc.introspectToken("opaque-test-token")
	if err != nil {
		t.Fatalf("introspectToken must succeed against the manual override endpoint, got: %v", err)
	}
	if !resp.Active {
		t.Fatal("introspectToken response Active = false, want true")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("introspection endpoint hit count = %d, want 1", got)
	}
	if gotToken != "opaque-test-token" {
		t.Fatalf("introspection request token = %q, want %q", gotToken, "opaque-test-token")
	}
}

// TestIssue152SiblingRevocationAndLogout proves the two dead siblings this
// issue repaired are wired end-to-end: RevokeTokenWithProvider
// (token_manager.go) posts to a configRevocationURL override, and the
// end-session URL BuildLogoutURL (helpers.go) builds from is the
// configEndSessionURL override. The full handleLogout HTTP handler needs a
// live SessionManager and an authenticated cookie to reach BuildLogoutURL,
// which is disproportionate for this fix; instead this asserts the live
// field wiring plus a direct BuildLogoutURL call with that wired value,
// which is the same function handleLogout calls.
func TestIssue152SiblingRevocationAndLogout(t *testing.T) {
	t.Run("RevokeTokenWithProvider posts to the override", func(t *testing.T) {
		var hits int32
		var gotToken string
		revocationSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			if err := r.ParseForm(); err == nil {
				gotToken = r.PostFormValue("token")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer revocationSrv.Close()

		oidc := &TraefikOidc{
			providerURL:         "https://provider.example.com",
			logger:              NewLogger("error"),
			clientID:            "test-client",
			clientSecret:        "test-secret",
			httpClient:          http.DefaultClient,
			configRevocationURL: revocationSrv.URL,
		}
		metadata := &ProviderMetadata{
			Issuer:   "https://provider.example.com",
			AuthURL:  "https://provider.example.com/authorize",
			TokenURL: "https://provider.example.com/token",
			JWKSURL:  "https://provider.example.com/jwks",
			// RevokeURL intentionally omitted.
		}
		oidc.updateMetadataEndpoints(metadata)

		if err := oidc.RevokeTokenWithProvider("opaque-test-token", "access_token"); err != nil {
			t.Fatalf("RevokeTokenWithProvider must succeed against the manual override endpoint, got: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 1 {
			t.Fatalf("revocation endpoint hit count = %d, want 1", got)
		}
		if gotToken != "opaque-test-token" {
			t.Fatalf("revocation request token = %q, want %q", gotToken, "opaque-test-token")
		}
	})

	t.Run("logout URL builder emits the override", func(t *testing.T) {
		overrideEndSession := "https://override.example.com/endsession"
		oidc := &TraefikOidc{
			providerURL:         "https://provider.example.com",
			logger:              NewLogger("error"),
			clientID:            "test-client",
			configEndSessionURL: overrideEndSession,
		}
		metadata := &ProviderMetadata{
			Issuer:   "https://provider.example.com",
			AuthURL:  "https://provider.example.com/authorize",
			TokenURL: "https://provider.example.com/token",
			JWKSURL:  "https://provider.example.com/jwks",
			// EndSessionURL intentionally omitted.
		}
		oidc.updateMetadataEndpoints(metadata)

		_, endSession, _ := issue152Endpoints(oidc)
		if endSession != overrideEndSession {
			t.Fatalf("endSessionURL = %q, want override %q wired before building the logout URL", endSession, overrideEndSession)
		}

		logoutURL, err := BuildLogoutURL(endSession, "idtok123", "https://myapp.example.com/")
		if err != nil {
			t.Fatalf("BuildLogoutURL must succeed with the wired override, got: %v", err)
		}
		if !strings.HasPrefix(logoutURL, overrideEndSession+"?") {
			t.Fatalf("logoutURL = %q, want prefix %q", logoutURL, overrideEndSession+"?")
		}
		if !strings.Contains(logoutURL, "id_token_hint=idtok123") {
			t.Fatalf("logoutURL = %q, want it to contain the id_token_hint", logoutURL)
		}
	})
}

// TestIssue152ConfigValidation pins Config.Validate's IntrospectionURL check:
// empty is fine (feature is opt-in), a valid HTTPS URL is fine, plaintext
// HTTP is fine only for a loopback host (isValidSecureURL's RFC 8252-style
// allowance, mirrored from the ProviderURL/RevocationURL/OIDCEndSessionURL
// checks), and anything else — plaintext HTTP to a remote host, or a
// malformed URL — is rejected with the introspectionURL-specific message.
func TestIssue152ConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
	}{
		{"valid HTTPS URL", "https://idp.example.com/introspect", false, ""},
		{"empty is valid (opt-in feature)", "", false, ""},
		{"plaintext HTTP allowed for loopback", "http://localhost:8080/introspect", false, ""},
		{"plaintext HTTP rejected for remote host", "http://evil.example.com/x", true, "introspectionURL must be a valid HTTPS URL"},
		{"malformed URL rejected", "://garbage", true, "introspectionURL must be a valid HTTPS URL"},
		{"URL with no host rejected", "https:///nohost", true, "introspectionURL must be a valid HTTPS URL"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := issue152BaseConfig()
			cfg.IntrospectionURL = tc.value

			err := cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() with IntrospectionURL=%q must fail", tc.value)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() with IntrospectionURL=%q must succeed, got: %v", tc.value, err)
			}
		})
	}
}

// TestIssue152InvalidIntrospectionURLNewContract proves an invalid
// IntrospectionURL is rejected by New() through the same fail-closed,
// untyped-nil-handler contract issue #151 established for every other
// Config.Validate failure: a concrete "invalid configuration" error, and h
// itself must be an untyped nil (not a typed-nil *TraefikOidc boxed into a
// non-nil http.Handler interface value).
func TestIssue152InvalidIntrospectionURLNewContract(t *testing.T) {
	cfg := issue152BaseConfig()
	cfg.IntrospectionURL = "http://evil.example.com/x" // plaintext HTTP to a remote host: rejected.

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	h, err := New(context.Background(), next, cfg, "issue152-invalid-introspection")
	if err == nil {
		t.Fatal("New() must reject an invalid IntrospectionURL")
	}
	if !strings.Contains(err.Error(), "invalid configuration") {
		t.Fatalf("New() error = %q, want it to contain %q", err.Error(), "invalid configuration")
	}
	if h != nil {
		t.Fatalf("New() must return an untyped nil handler on error, got %T", h)
	}
}
