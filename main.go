package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

var (
	infoLogger = log.New(io.Discard, "INFO: traefikoidc: ", log.Ldate|log.Ltime)
)

type TraefikOidc struct {
	next           http.Handler
	name           string
	store          *sessions.CookieStore
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

	metadata, err := discoverProviderMetadata(config.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover provider metadata: %v", err)
	}

	return &TraefikOidc{
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
	}, nil
}

func discoverProviderMetadata(providerURL string) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch provider metadata: status code %d", resp.StatusCode)
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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
	t.scheme = scheme

	host := req.URL.Host
	if host == "" {
		host = req.Header.Get("X-Forwarded-Host")
	}
	if host == "" {
		host = req.Host
	}

	// infoLogger.Printf("Scheme: %s, Host: %s, Path: %s", scheme, host, t.redirURLPath)
	// infoLogger.Printf("X-Forwarded-Proto: %s", req.Header.Get("X-Forwarded-Proto"))
	// infoLogger.Printf("X-Forwarded-Host: %s", req.Header.Get("X-Forwarded-Host"))
	redirectURL := assembleRedirectURL(t.scheme, host, t.redirURLPath)
	// infoLogger.Printf("Final redirect URL: %s", redirectURL)

	session, err := t.store.Get(req, cookie_name)
	if err != nil {
		// infoLogger.Printf("Error getting session: %v", err)
		http.Error(rw, "Session error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if req.URL.Path == t.redirURLPath {
		// infoLogger.Printf("Handling callback, URL: %s", req.URL.String())
		authSuccess, originalPath := t.handleCallback(rw, req)
		if authSuccess {
			http.Redirect(rw, req, originalPath, http.StatusFound)
			return
		}
		// If auth was not successful, return an error instead of re-authenticating
		http.Error(rw, "Authentication failed", http.StatusUnauthorized)
		return
	}

	authenticated, _ := session.Values["authenticated"].(bool)
	if authenticated {
		idToken, ok := session.Values["id_token"].(string)
		if !ok || idToken == "" {
			http.Error(rw, "Invalid session", http.StatusUnauthorized)
			return
		}

		if err := t.verifyToken(idToken); err != nil {
			http.Error(rw, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Proceed with the request
		t.next.ServeHTTP(rw, req)
		return
	}

	// User is not authenticated, start the auth process
	csrfToken := uuid.New().String()
	session.Values["csrf"] = csrfToken
	session.Values["incoming_path"] = req.URL.Path
	// infoLogger.Printf("Setting CSRF token: %s", csrfToken)
	err = session.Save(req, rw)
	if err != nil {
		// infoLogger.Printf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify the session was saved correctly
	verifySession, _ := t.store.Get(req, cookie_name)
	savedCSRF, ok := verifySession.Values["csrf"].(string)
	if !ok || savedCSRF != csrfToken {
		// infoLogger.Printf("Failed to save CSRF token. Saved: %s, Expected: %s", savedCSRF, csrfToken)
		http.Error(rw, "Failed to save CSRF token", http.StatusInternalServerError)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

func (t *TraefikOidc) isUserAuthenticated(req *http.Request) bool {
	session, err := t.store.Get(req, cookie_name)
	if err != nil {
		return false
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		return false
	}

	return true
}

func (t *TraefikOidc) verifyToken(token string) error {
	if !t.limiter.Allow() {
		return errors.New("rate limit exceeded")
	}

	jwt, err := parseJWT(token)
	if err != nil {
		return err
	}

	jwks, err := t.jwkCache.GetJWKS(t.jwksURL)
	if err != nil {
		return err
	}

	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return errors.New("missing key ID in token header")
	}

	var publicKeyPEM []byte
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			publicKeyPEM, err = jwkToPEM(&key)
			if err != nil {
				return err
			}
			break
		}
	}

	if publicKeyPEM == nil {
		return errors.New("unable to find matching public key")
	}

	if err := verifySignature(token, publicKeyPEM); err != nil {
		return err
	}

	if err := verifyAudience(jwt.Claims["aud"].(string), t.clientID); err != nil {
		return err
	}

	if err := jwt.Verify(t.issuerURL, t.clientID); err != nil {
		return err
	}

	if err := verifyTokenTimes(
		int64(jwt.Claims["iat"].(float64)),
		int64(jwt.Claims["exp"].(float64)),
		5*time.Minute, // Allowed clock skew
	); err != nil {
		return err
	}

	if err := validateClaims(jwt.Claims); err != nil {
		return err
	}

	return nil
}

func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce string) string {
	params := url.Values{}
	params.Add("client_id", t.clientID)
	params.Add("response_type", "code")
	params.Add("redirect_uri", redirectURL)
	params.Add("scope", strings.Join(t.scopes, " "))
	params.Add("state", state)
	params.Add("nonce", nonce)

	authURL := t.authURL + "?" + params.Encode()
	// infoLogger.Printf("Built auth URL: %s", authURL)
	return authURL
}
