package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSuccessHandler_Writes200(t *testing.T) {
	h := newSuccessHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
}

func TestSuccessHandler_MirrorsForwardedHeaders(t *testing.T) {
	h := newSuccessHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	req.Header.Set("X-Custom-Templated", "value")
	req.Header.Set("Authorization", "Bearer token-from-template")
	req.Header.Set("Cookie", "session=should-NOT-mirror")

	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Forwarded-User"); got != "alice@example.com" {
		t.Errorf("X-Forwarded-User: want mirrored, got %q", got)
	}
	if got := rec.Header().Get("X-Forwarded-Email"); got != "alice@example.com" {
		t.Errorf("X-Forwarded-Email: want mirrored, got %q", got)
	}
	if got := rec.Header().Get("X-Custom-Templated"); got != "value" {
		t.Errorf("X-Custom-Templated: want mirrored (X- prefix), got %q", got)
	}
	if got := rec.Header().Get("Authorization"); got != "Bearer token-from-template" {
		t.Errorf("Authorization: want mirrored (templated bearer), got %q", got)
	}
	if got := rec.Header().Get("Cookie"); got != "" {
		t.Errorf("Cookie must NOT be mirrored, got %q", got)
	}
}

func TestSuccessHandler_EmptyBody(t *testing.T) {
	h := newSuccessHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Fatalf("body: want empty, got %q", body)
	}
}
