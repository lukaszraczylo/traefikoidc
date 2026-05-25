package main

import "net/http"

// readyReporter is satisfied by *traefikoidc.TraefikOidc via its Ready() method.
type readyReporter interface {
	Ready() bool
}

func newHealthzHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
}

func newReadyzHandler(r readyReporter) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if r.Ready() {
			rw.WriteHeader(http.StatusOK)
			return
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
	})
}
