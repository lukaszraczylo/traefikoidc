package traefikoidc

import (
	"context"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type TraefikOidc struct {
	next        http.Handler
	name        string
	provider    *oidc.Provider
	oauthConfig oauth2.Config
	store       *sessions.CookieStore
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	provider, err := oidc.NewProvider(ctx, config.ProviderURL)
	if err != nil {
		log.Fatal("Can't connect to the provider", err)
		return nil, err
	}

	store := sessions.NewCookieStore([]byte(config.SessionEncryptionKey))

	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.CallbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, config.Scopes...),
	}

	return &TraefikOidc{
		provider:    provider,
		oauthConfig: oauthConfig,
		next:        next,
		name:        name,
		store:       store,
	}, nil
}

func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path == t.oauthConfig.RedirectURL {
		t.handleCallback(rw, req)
		return
	}

	session, err := t.store.Get(req, "session-name")
	if err != nil {
		http.Error(rw, "Session error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if t.isUserAuthenticated(req) {
		t.next.ServeHTTP(rw, req)
	}

	csrfToken := uuid.New().String()
	session.Values["csrf"] = csrfToken
	err = session.Save(req, rw)
	if err != nil {
		http.Error(rw, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Use the CSRF token as the OIDC "state" parameter for CSRF protection
	redirectURL := t.oauthConfig.AuthCodeURL(csrfToken, oidc.Nonce(uuid.New().String()))
	http.Redirect(rw, req, redirectURL, http.StatusFound)
}

func (t *TraefikOidc) isUserAuthenticated(req *http.Request) bool {
	session, err := t.store.Get(req, "session-name")
	if err != nil {
		return false
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		return false
	}

	return true
}
