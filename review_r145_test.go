package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func r145BaseConfig() *Config {
	c := CreateConfig()
	c.ProviderURL = "https://provider.example.com"
	c.ClientID = "test-client"
	c.ClientSecret = "test-secret"
	c.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	c.CallbackURL = "/callback"
	return c
}

// TestConfigValidates_RefreshDurationOverflow guards the R145 fix in
// settings.go Validate: RefreshGracePeriodSeconds and
// MaxRefreshTokenAgeSeconds are converted to time.Duration as
// time.Duration(x) * time.Second at startup. Values above
// ~9.22e9 seconds overflow int64 nanoseconds and wrap negative — a
// wrapped-negative grace pulls the refresh threshold into the past
// (perpetual refresh), and a wrapped-negative max-age marks every
// session refresh-token-expired (mass re-auth). This is the same bug
// class already guarded for SessionMaxAge (R141), now extended here.
func TestConfigValidates_RefreshDurationOverflow(t *testing.T) {
	for _, field := range []string{"refreshGracePeriodSeconds", "maxRefreshTokenAgeSeconds"} {
		t.Run(field, func(t *testing.T) {
			c := r145BaseConfig()
			switch field {
			case "refreshGracePeriodSeconds":
				c.RefreshGracePeriodSeconds = 10_000_000_000
			case "maxRefreshTokenAgeSeconds":
				c.MaxRefreshTokenAgeSeconds = 10_000_000_000
			}
			if err := c.Validate(); err == nil {
				t.Fatalf("out-of-range %s (would overflow time.Duration at startup) must be rejected by Validate", field)
			}
		})
	}
}

// TestConfigValidates_CookieDomain guards the R145 fix in settings.go
// Validate: cookieDomain is applied verbatim to the session cookie's
// Domain option. An invalid value (a full URL, or chars illegal in a
// cookie domain) makes every browser reject the Set-Cookie, surfacing
// only as a login loop at runtime; it must fail at startup instead.
func TestConfigValidates_CookieDomain(t *testing.T) {
	urlDomain := r145BaseConfig()
	urlDomain.CookieDomain = "https://example.com"
	if err := urlDomain.Validate(); err == nil {
		t.Fatal("cookieDomain as a full URL must be rejected by Validate")
	}

	badChars := r145BaseConfig()
	badChars.CookieDomain = "exa mple.com;user"
	if err := badChars.Validate(); err == nil {
		t.Fatal("cookieDomain with illegal characters must be rejected by Validate")
	}

	valid := r145BaseConfig()
	valid.CookieDomain = ".example.com"
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid bare cookie domain must pass Validate, got: %v", err)
	}
}

// TestCleanupOldCookies_DeleteCookieSecureCaseInsensitive guards the R145
// fix in session.go CleanupOldCookies: the delete-cookie Secure
// attribute compared X-Forwarded-Proto case-sensitively (an exact
// residual of the R143 goto for session.Save). A proxy emitting a
// non-canonical "HTTPS" value downgraded even the deletion cookie to
// non-Secure. The check must be case-insensitive.
func TestCleanupOldCookies_DeleteCookieSecureCaseInsensitive(t *testing.T) {
	sm, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "app.example.com", "testpref", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-Proto", "HTTPS")
	req.AddCookie(&http.Cookie{Name: "testpref_sess", Value: "x"})
	rw := httptest.NewRecorder()

	sm.CleanupOldCookies(rw, req)

	anySecure := false
	for _, c := range rw.Result().Cookies() {
		if c.Secure {
			anySecure = true
			break
		}
	}
	if !anySecure {
		t.Fatal("a non-canonical (uppercase) X-Forwarded-Proto https value must still yield a Secure delete cookie")
	}
}

// TestCallback_ErrorDescriptionSanitized guards the R145 fix in
// auth_flow.go handleCallback: the provider error / error_description
// query params are attacker-controlled and were concatenated verbatim
// into the log line and echoed into the error response. An embedded
// newline could inject a forged line into structured logs; unbounded
// length would bloat the log and response. Values must be
// newline-sanitized and length-capped.
func TestCallback_ErrorDescriptionSanitized(t *testing.T) {
	sm, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sm.Shutdown()

	oidc := &TraefikOidc{
		logger:         newNoOpLogger(),
		sessionManager: sm,
	}

	desc := "line1%0Aline2"
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description="+desc, nil)
	rw := httptest.NewRecorder()

	oidc.handleCallback(rw, req, "/")

	body := rw.Body.String()
	if strings.Contains(body, "line1\nline2") {
		t.Fatalf("callback error body must not contain a raw newline from error_description (log/response injection), got %q", body)
	}
	if !strings.Contains(body, "line1 line2") {
		t.Fatalf("callback error body must contain the newline-sanitized error_description")
	}
}
