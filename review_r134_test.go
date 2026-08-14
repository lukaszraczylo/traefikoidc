package traefikoidc

// R134 config-validation regressions.
//
// (a) LogoutURL is matched by exact request-path comparison at runtime, so a
// query string / fragment / relative-relative value silently breaks RP-initiated
// logout. It must be rejected at config time like CallbackURL.
//
// (b) EnableBearerAuth=true requires an explicit Audience (it cannot default to
// clientID, which accepts ID tokens). This was enforced only in the
// NewWithContext constructor; a standalone Config.Validate() must also fail
// closed.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type r134RoundTripper struct {
	roundTrips atomic.Int32
}

func (r *r134RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.roundTrips.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestRevokeTokenWithProvider_NoDataRaceWithDCRCredentialWrite guards the fix
// for a data race: RevokeTokenWithProvider read t.clientID/clientSecret
// unlocked while DCR (registerWithProvider) writes them under
// metadataMu.Lock. Run with -race; the revocation goroutine re-reads the
// credentials repeatedly while a concurrent goroutine rotates them under the
// lock, so an unlocked read is flagged (R134).
func TestRevokeTokenWithProvider_NoDataRaceWithDCRCredentialWrite(t *testing.T) {
	rt := &r134RoundTripper{}
	oidc := &TraefikOidc{
		logger:           newNoOpLogger(),
		httpClient:       &http.Client{Transport: rt},
		revocationURL:    "https://provider.example.com/revoke",
		clientID:         "client-id",
		clientSecret:     "client-secret",
		clientAuthMethod: "client_secret_post",
		issuerURL:        "https://provider.example.com",
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			if err := oidc.RevokeTokenWithProvider("tok", "refresh_token"); err != nil {
				t.Errorf("RevokeTokenWithProvider: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			oidc.metadataMu.Lock()
			oidc.clientID = fmt.Sprintf("new-client-%d", i)
			oidc.clientSecret = fmt.Sprintf("new-secret-%d", i)
			oidc.metadataMu.Unlock()
		}
	}()
	wg.Wait()

	if rt.roundTrips.Load() == 0 {
		t.Fatal("expected revocation requests to be sent")
	}
}

func r134ValidConfig() *Config {
	return &Config{
		ProviderURL:          "https://provider.example.com",
		CallbackURL:          "/callback",
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		SessionEncryptionKey: "0123456789abcdef0123456789abcdef",
		RateLimit:            CreateConfig().RateLimit,
	}
}

func TestValidate_LogoutURL_MustBeBarePath(t *testing.T) {
	cases := []struct {
		name      string
		logoutURL string
		wantErr   bool
	}{
		{"valid bare path", "/logout", false},
		{"empty allowed (defaults to callback+logout)", "", false},
		{"query string breaks exact-match", "/logout?tenant=1", true},
		{"fragment breaks exact-match", "/logout#frag", true},
		{"relative value not a path", "logout", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := r134ValidConfig()
			c.LogoutURL = tt.logoutURL
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() with LogoutURL=%q err=%v, wantErr=%v", tt.logoutURL, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_EnableBearerAuthRequiresAudience(t *testing.T) {
	// Fail-on-old: before R134, Validate() returned nil here because the
	// bearer-requires-audience rule lived only in the constructor.
	c := r134ValidConfig()
	c.EnableBearerAuth = true
	c.Audience = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to require Audience when EnableBearerAuth=true")
	}

	c.Audience = "https://api.example.com"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid with audience set, got %v", err)
	}
}
