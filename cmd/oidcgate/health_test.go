package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type readyStub struct{ ready bool }

func (r *readyStub) Ready() bool { return r.ready }

func TestHealthz_Always200(t *testing.T) {
	h := newHealthzHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
}

func TestReadyz_503BeforeDiscovery(t *testing.T) {
	h := newReadyzHandler(&readyStub{ready: false})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz pre-discovery: want 503, got %d", rec.Code)
	}
}

func TestReadyz_200AfterDiscovery(t *testing.T) {
	h := newReadyzHandler(&readyStub{ready: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz post-discovery: want 200, got %d", rec.Code)
	}
}
