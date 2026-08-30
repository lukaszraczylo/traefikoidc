package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"text/template"
	"time"
)

// ttlRecordingCache is a CacheInterface that records the TTL passed to Set
// so tests can assert the invalidation TTL tracks session max age.
type ttlRecordingCache struct {
	mu   sync.Mutex
	ttls map[string]time.Duration
}

func (c *ttlRecordingCache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ttls == nil {
		c.ttls = make(map[string]time.Duration)
	}
	c.ttls[key] = ttl
}
func (c *ttlRecordingCache) Get(key string) (any, bool) { return nil, false }
func (c *ttlRecordingCache) Delete(key string)          {}
func (c *ttlRecordingCache) SetMaxSize(int)             {}
func (c *ttlRecordingCache) Size() int                  { return 0 }
func (c *ttlRecordingCache) Clear()                     {}
func (c *ttlRecordingCache) Cleanup()                   {}
func (c *ttlRecordingCache) Close()                     {}
func (c *ttlRecordingCache) GetStats() map[string]any   { return nil }

// TestBackchannelInvalidationTTL_TracksSessionMaxAge is a regression for the
// hardcoded 25h invalidation TTL: when the session max age is configured
// longer than 25h, the invalidation entry must outlive the cookie, or a
// replayed dead cookie would be re-accepted after the entry lapses. The
// fix derives the invalidation TTL from the session manager's max age.
func TestBackchannelInvalidationTTL_TracksSessionMaxAge(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	if oidc.sessionManager == nil {
		t.Fatal("expected a session manager from makeBearerOIDC")
	}
	oidc.sessionManager.sessionMaxAge = 48 * time.Hour
	if oidc.logger == nil {
		oidc.logger = NewLogger("debug")
	}
	rec := &ttlRecordingCache{}
	oidc.sessionInvalidationCache = rec

	if err := oidc.invalidateSession("sid-t", "sub-t"); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}

	const sidKey = "session_invalidation:sid:sid-t"
	rec.mu.Lock()
	ttl, ok := rec.ttls[sidKey]
	rec.mu.Unlock()
	if !ok {
		t.Fatalf("sid invalidation not recorded (key %q)", sidKey)
	}
	if ttl < 48*time.Hour {
		t.Fatalf("invalidation TTL %v must track session max age (>= 48h), got a fixed short TTL", ttl)
	}
}

// TestHeaderTemplate_EmptyRender_DoesNotClobberIdentity is a regression for
// an operator-header template that renders an empty value: the old code
// req.Header.Set(name, "") after identity headers were already injected,
// silently blanking X-Forwarded-User with the authenticated identifier.
// The fix skips an empty render so the identity header survives.
func TestHeaderTemplate_EmptyRender_DoesNotClobberIdentity(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	oidc := &TraefikOidc{
		logger: NewLogger("debug"),
		next:   next,
		headerTemplates: map[string]*template.Template{
			"X-Forwarded-User": template.Must(template.New("t").Parse("{{.Claims.email}}")),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rw := httptest.NewRecorder()
	oidc.forwardAuthorized(rw, req, &principal{
		Identifier: "alice@example.com",
		Claims:     map[string]interface{}{"sub": "alice"}, // no email -> template renders empty
	})

	if got := req.Header.Get("X-Forwarded-User"); got != "alice@example.com" {
		t.Fatalf("identity header clobbered by empty template render: got %q, want %q", got, "alice@example.com")
	}
}
