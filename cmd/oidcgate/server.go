package main

import (
	"context"
	"net/http"
	"time"
)

// buildMux wires all six routes onto a single ServeMux:
//
//	/healthz, /readyz, AuthPath, StartPath, OIDC.CallbackURL, OIDC.LogoutURL.
//
// The same `middleware` instance is delegated to by all four OIDC routes;
// the synthetic success handler is wired into the middleware at construction
// time (in main.go) so it doesn't appear here.
func buildMux(cfg *Config, middleware http.Handler, ready readyReporter) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/healthz", newHealthzHandler())
	mux.Handle("/readyz", newReadyzHandler(ready))
	mux.Handle(cfg.AuthPath, newAuthHandler(middleware))
	mux.Handle(cfg.StartPath, newStartHandler(middleware))
	mux.Handle(cfg.OIDC.CallbackURL, newCallbackHandler(middleware, cfg.OIDC.CallbackURL))
	mux.Handle(cfg.OIDC.LogoutURL, newLogoutHandler(middleware, cfg.OIDC.LogoutURL))
	return mux
}

// buildServer wraps the mux in an http.Server with sensible timeouts.
func buildServer(cfg *Config, mux http.Handler) *http.Server { //nolint:unused // consumed by main.go in Task 9
	return &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// shutdown gracefully stops the server with a 15s deadline.
func shutdown(srv *http.Server) error { //nolint:unused // consumed by main.go in Task 9
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
