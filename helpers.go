package traefikoidc

import (
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
)

func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	session, err := t.store.Get(req, "session-name")
	if err != nil {
		http.Error(rw, "Session error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Compare the CSRF token from the session with the "state" parameter from the callback
	callbackState := req.URL.Query().Get("state")
	if sessionState, ok := session.Values["csrf"].(string); !ok || callbackState != sessionState {
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	oauth2Token, err := t.oauthConfig.Exchange(ctx, req.URL.Query().Get("code"))
	if err != nil {
		http.Error(rw, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(rw, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	_, err = t.provider.Verifier(&oidc.Config{ClientID: t.oauthConfig.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(rw, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["authenticated"] = true
	session.Values["id_token"] = rawIDToken
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true, // Ensure cookies are sent over HTTPS
	}
	err = session.Save(req, rw)
	if err != nil {
		http.Error(rw, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
