package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInterceptor_302BecomesNot401(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)

	w.Header().Set("Location", "https://idp.example/authorize?state=abc")
	w.Header().Add("Set-Cookie", "_oidc_state=abc; Path=/; HttpOnly")
	w.Header().Add("Set-Cookie", "_oidc_pkce=xyz; Path=/; HttpOnly")
	w.WriteHeader(http.StatusFound)
	_, _ = w.Write([]byte("ignored body"))

	w.Finalize()

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Redirect"); got != "https://idp.example/authorize?state=abc" {
		t.Errorf("X-Auth-Redirect: want preserved Location, got %q", got)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("Location must be stripped on 401, got %q", got)
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("Set-Cookie count: want 2, got %d (%v)", len(cookies), cookies)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("body must be empty on 401, got %q", body)
	}
}

func TestInterceptor_NonRedirectPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)

	w.Header().Set("X-Forwarded-User", "alice")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))

	w.Finalize()

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Forwarded-User"); got != "alice" {
		t.Errorf("X-Forwarded-User: want preserved, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("body: want 'ok' preserved, got %q", rec.Body.String())
	}
}

func TestInterceptor_303SeeOtherAlsoIntercepted(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)
	w.Header().Set("Location", "/elsewhere")
	w.WriteHeader(http.StatusSeeOther)
	w.Finalize()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("303 should be intercepted to 401, got %d", rec.Code)
	}
}

func TestInterceptor_307TemporaryRedirectIntercepted(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)
	w.Header().Set("Location", "/elsewhere")
	w.WriteHeader(http.StatusTemporaryRedirect)
	w.Finalize()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("307 should be intercepted to 401, got %d", rec.Code)
	}
}

func TestInterceptor_308PermanentRedirectIntercepted(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)
	w.Header().Set("Location", "/elsewhere")
	w.WriteHeader(http.StatusPermanentRedirect)
	w.Finalize()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("308 should be intercepted to 401, got %d", rec.Code)
	}
}

func TestInterceptor_DoubleFinalizeIsNoop(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newAuthInterceptor(rec)
	w.Header().Set("X-Forwarded-User", "alice")
	w.WriteHeader(http.StatusOK)
	w.Finalize()
	// Second call must not panic, must not change anything observable.
	w.Finalize()
	if rec.Code != http.StatusOK {
		t.Fatalf("double Finalize must not change status, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Forwarded-User"); got != "alice" {
		t.Errorf("double Finalize must not duplicate headers, got %q", got)
	}
}
