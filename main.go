package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

type TraefikOidc struct {
	next           http.Handler
	name           string
	store          sessions.Store
	redirURLPath   string
	issuerURL      string
	jwkCache       *JWKCache
	tokenBlacklist *TokenBlacklist
	jwksURL        string
	clientID       string
	clientSecret   string
	authURL        string
	tokenURL       string
	scopes         []string
	limiter        *rate.Limiter
	forceHTTPS     bool
	scheme         string
	tokenCache     *TokenCache
	httpClient     HTTPClient
	logger         Logger
}

type ProviderMetadata struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	store := sessions.NewCookieStore([]byte(config.SessionEncryptionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	metadata, err := discoverProviderMetadata(config.ProviderURL, &http.Client{})
	if err != nil {
		return nil, fmt.Errorf("failed to discover provider metadata: %w", err)
	}
	logger := NewLogger(config.LogLevel)

	t := &TraefikOidc{
		next:           next,
		name:           name,
		store:          store,
		redirURLPath:   config.CallbackURL,
		issuerURL:      metadata.Issuer,
		tokenBlacklist: NewTokenBlacklist(),
		jwkCache:       &JWKCache{},
		jwksURL:        metadata.JWKSURL,
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		forceHTTPS:     config.ForceHTTPS,
		authURL:        metadata.AuthURL,
		tokenURL:       metadata.TokenURL,
		scopes:         config.Scopes,
		limiter:        rate.NewLimiter(rate.Every(time.Second), 100),
		tokenCache:     NewTokenCache(),
		httpClient:     &http.Client{},
		logger:         logger,
	}

	t.startTokenCleanup()
	return t, nil
}

func discoverProviderMetadata(providerURL string, httpClient HTTPClient) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch provider metadata: status code %d", resp.StatusCode)
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode provider metadata: %w", err)
	}

	return &metadata, nil
}

func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	t.scheme = t.determineScheme(req)
	host := t.determineHost(req)

	redirectURL := buildFullURL(t.scheme, host, t.redirURLPath)
	t.logger.Infof("Final redirect URL: %s", redirectURL)

	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	if req.URL.Path == t.redirURLPath {
		t.logger.Infof("Handling callback, URL: %s", req.URL.String())
		authSuccess, originalPath := t.handleCallback(rw, req)
		if authSuccess {
			http.Redirect(rw, req, originalPath, http.StatusFound)
			return
		}
		http.Error(rw, "Authentication failed", http.StatusUnauthorized)
		return
	}

	if t.isUserAuthenticated(session) {
		t.next.ServeHTTP(rw, req)
		return
	}

	// User is not authenticated, start the auth process
	t.initiateAuthentication(rw, req, session, redirectURL)
}

func (t *TraefikOidc) determineScheme(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = req.Header.Get("X-Forwarded-Proto")
	}
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if t.forceHTTPS {
		scheme = "https"
	}
	return scheme
}

func (t *TraefikOidc) determineHost(req *http.Request) string {
	host := req.URL.Host
	if host == "" {
		host = req.Header.Get("X-Forwarded-Host")
	}
	if host == "" {
		host = req.Host
	}
	return host
}

func (t *TraefikOidc) isUserAuthenticated(session *sessions.Session) bool {
	authenticated, _ := session.Values["authenticated"].(bool)
	if authenticated {
		idToken, ok := session.Values["id_token"].(string)
		if !ok || idToken == "" {
			return false
		}
		return t.verifyToken(idToken) == nil
	}
	return false
}

func (t *TraefikOidc) initiateAuthentication(rw http.ResponseWriter, req *http.Request, session *sessions.Session, redirectURL string) {
	csrfToken := uuid.New().String()
	session.Values["csrf"] = csrfToken
	session.Values["incoming_path"] = req.URL.Path
	t.logger.Infof("Setting CSRF token: %s", csrfToken)

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

func (t *TraefikOidc) verifyToken(token string) error {
	return t.verifyAndCacheToken(token)
}

func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce string) string {
	params := url.Values{
		"client_id":     {t.clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURL},
		"scope":         {strings.Join(t.scopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}

	return fmt.Sprintf("%s?%s", t.authURL, params.Encode())
}

func (t *TraefikOidc) startTokenCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			t.tokenCache.Cleanup()
			t.tokenBlacklist.Cleanup()
		}
	}()
}
