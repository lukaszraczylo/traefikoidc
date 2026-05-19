package main

import "github.com/lukaszraczylo/traefikoidc"

type traefikoidcConfigStub struct {
	callbackURL string
	logoutURL   string
}

func (s traefikoidcConfigStub) AsOIDC() traefikoidc.Config {
	return traefikoidc.Config{
		CallbackURL: s.callbackURL,
		LogoutURL:   s.logoutURL,
	}
}
