package traefikoidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"
)

// ---- jti replay protection (OIDC Back-Channel Logout 1.0 §2.5) ----

type replayJWKCache struct{ jwks *JWKSet }

func (r *replayJWKCache) GetJWKS(ctx context.Context, u string, c *http.Client) (*JWKSet, error) {
	return r.jwks, nil
}
func (r *replayJWKCache) GetPublicKey(ctx context.Context, u, kid string, c *http.Client) (crypto.PublicKey, error) {
	for i := range r.jwks.Keys {
		if r.jwks.Keys[i].Kid == kid {
			switch r.jwks.Keys[i].Kty {
			case "EC":
				return r.jwks.Keys[i].ToECDSAPublicKey()
			case "RSA":
				return r.jwks.Keys[i].ToRSAPublicKey()
			}
		}
	}
	return nil, fmt.Errorf("missing key %s", kid)
}
func (r *replayJWKCache) Clear()   {}
func (r *replayJWKCache) Cleanup() {}
func (r *replayJWKCache) Close()   {}

// TestBackchannelLogout_RejectsReplayedJTI regresses the missing jti
// replay protection in validateLogoutToken: per OIDC BCL §2.5 the same
// logout token must be rejected on a second submission. Before the fix a
// captured token could be re-applied within its iat window and force-logout
// a session a user re-established after the genuine logout.
func TestBackchannelLogout_RejectsReplayedJTI(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes())

	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: &mockCacheInterface{data: map[string]interface{}{}},
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache: &replayJWKCache{jwks: &JWKSet{Keys: []JWK{{
			Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256",
		}}}},
	}

	token := func() string {
		h, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "logout+jwt", "kid": "test-key-1"})
		hb := base64.RawURLEncoding.EncodeToString(h)
		c, _ := json.Marshal(map[string]interface{}{
			"iss": "https://provider.example.com",
			"aud": "test-client",
			"iat": time.Now().Unix(),
			"jti": "unique-jti-123",
			"events": map[string]interface{}{
				"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
			},
			"sid": "session-to-logout",
		})
		cb := base64.RawURLEncoding.EncodeToString(c)
		hash := sha256.Sum256([]byte(hb + "." + cb))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
		sig := make([]byte, 64)
		rb, sb := r.Bytes(), s.Bytes()
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):], sb)
		return hb + "." + cb + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
			strings.NewReader("logout_token="+url.QueryEscape(token())))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rw := httptest.NewRecorder()
		oidc.handleBackchannelLogout(rw, req)
		return rw.Code
	}

	if code := post(); code != http.StatusOK {
		t.Fatalf("first logout token accepted? got %d, expected 200", code)
	}
	if code := post(); code != http.StatusBadRequest {
		t.Fatalf("replayed logout token should be rejected (400), got %d", code)
	}
}

// ---- expired-token AJAX guard ----

// TestServeHTTP_ExpiredAjaxReturns401 regresses the expired-token branch
// sending an AJAX/sub-resource request down a 302 to the IdP. It must
// answer 401 like the sibling branches so sub-resource loads to not
// overwrite the in-flight session's CSRF/nonce.
func TestServeHTTP_ExpiredAjaxReturns401(t *testing.T) {
	sessionManager := createTestSessionManager(t)
	oidc := &TraefikOidc{
		next:                         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               sessionManager,
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
		redirURLPath:                 "/callback",
		logoutURLPath:                "/logout",
		clientID:                     "test-client",
		audience:                     "test-client",
		// Access-token verification reports "token has expired" and the
		// session has no refresh or ID token -> isUserAuthenticatedRS sets
		// expired=true, reaching the branch under test.
		tokenVerifier: &EnhancedMockTokenVerifier{VerifyFunc: func(token string) error { return errors.New("token has expired") }},
	}
	close(oidc.initComplete)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	_ = session.SetAuthenticated(true)
	session.SetAccessToken("aaa.bbb.ccc")
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expired-token AJAX request: expected 401, got %d (Location=%q)", rw.Code, rw.Header().Get("Location"))
	}
}

// ---- missing claim renders no '<no value>' ----

func mustTemplate(src string) *template.Template {
	tmpl, err := template.New("h").Parse(src)
	if err != nil {
		panic(err)
	}
	return tmpl
}

// TestHeaderTemplate_MissingClaimNoNoValue regresses optional claims
// rendering literal "<no value>" into a downstream header when the
// provider does not emit them (e.g. email, given_name).
func TestHeaderTemplate_MissingClaimNoNoValue(t *testing.T) {
	oidc := &TraefikOidc{
		next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:         NewLogger("error"),
		groupClaimName: "groups",
		roleClaimName:  "roles",
		minimalHeaders: true,
		headerTemplates: map[string]*template.Template{
			"X-Email": mustTemplate("{{.Claims.email}}"),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	p := &principal{Identifier: "user", Claims: map[string]interface{}{"sub": "subject"}}
	oidc.forwardAuthorized(rw, req, p)

	if got := req.Header.Get("X-Email"); got != "" {
		t.Fatalf("expected empty header for a missing claim, got %q", got)
	}
}
