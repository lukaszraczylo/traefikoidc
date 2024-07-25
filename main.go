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
	logoutURLPath  string
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
	httpClient     *http.Client
	logger         *Logger
	redirectURL    string
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

	metadata, err := discoverProviderMetadata(config.ProviderURL, http.Client{})
	if err != nil {
		return nil, fmt.Errorf("failed to discover provider metadata: %w", err)
	}

	t := &TraefikOidc{
		next:           next,
		name:           name,
		store:          store,
		redirURLPath:   config.CallbackURL,
		logoutURLPath:  config.LogoutURL,
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
		limiter:        rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:     NewTokenCache(),
		httpClient:     &http.Client{},
		logger:         NewLogger(config.LogLevel),
		redirectURL:    "",
	}
	t.startTokenCleanup()
	return t, nil
}

func discoverProviderMetadata(providerURL string, httpClient http.Client) (*ProviderMetadata, error) {
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

	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		http.Error(rw, "Logged out", http.StatusForbidden)
		return
	}

	if t.redirectURL == "" {
		t.redirectURL = buildFullURL(t.scheme, host, t.redirURLPath)
		t.logger.Debugf("Redirect URL updated to: %s", t.redirectURL)
	}

	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	if req.URL.Path == t.redirURLPath {
		t.logger.Debugf("Handling callback, URL: %s", req.URL.String())
		authSuccess, originalPath := t.handleCallback(rw, req)
		if authSuccess {
			http.Redirect(rw, req, originalPath, http.StatusFound)
			return
		}
		http.Error(rw, "Authentication failed", http.StatusUnauthorized)
		return
	}

	if t.isUserAuthenticated(session) {
		t.logger.Debugf("User is authenticated, serving content")
		t.next.ServeHTTP(rw, req)
		return
	}

	// User is not authenticated or session has expired, start the auth process
	t.initiateAuthentication(rw, req, session, t.redirectURL)
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

		// Check if the token has expired
		claims, err := extractClaims(idToken)
		if err != nil {
			t.logger.Errorf("Failed to extract claims: %v", err)
			return false
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			t.logger.Errorf("Failed to get expiration time from claims")
			return false
		}

		if time.Now().Unix() > int64(exp) {
			t.logger.Debugf("Session has expired")
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
	t.logger.Debugf("Setting CSRF token: %s", csrfToken)

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
			t.logger.Debug("Cleaning up token cache")
			t.tokenCache.Cleanup()
			t.tokenBlacklist.Cleanup()
		}
	}()
}

func (t *TraefikOidc) RevokeToken(token string) {
	// Remove from cache
	t.tokenCache.Delete(token)

	// Add to blacklist
	claims, err := extractClaims(token)
	if err == nil {
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			t.tokenBlacklist.Add(token, expTime)
		}
	}
}
