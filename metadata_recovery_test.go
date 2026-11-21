package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFlakyDiscovery serves failStatus for the first failures discovery
// requests, then a valid document whose endpoints share the server's host.
// The returned provider URL is unique to the test, so the process-wide
// metadata cache never answers with another test's document.
func newFlakyDiscovery(t *testing.T, failStatus int, failures int32) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= failures {
			w.WriteHeader(failStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProviderMetadata{
			Issuer:   srv.URL,
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/" + strings.ReplaceAll(t.Name(), "/", "_"), hits
}

// fastRetry shrinks a retry config's delays so a test runs in milliseconds.
func fastRetry(cfg RetryConfig, attempts int) RetryConfig {
	cfg.MaxAttempts = attempts
	cfg.InitialDelay = time.Millisecond
	cfg.MaxDelay = time.Millisecond
	return cfg
}

// newRecoveryTestOIDC builds an instance whose provider metadata is not yet
// known and whose startup gate is still open, as New leaves it before init.
func newRecoveryTestOIDC(t *testing.T, srv *httptest.Server, providerURL string) *TraefikOidc {
	t.Helper()
	return newTestOIDC(t, func(o *TraefikOidc) {
		o.issuerURL = ""
		o.initComplete = make(chan struct{})
		o.providerURL = providerURL
		o.httpClient = srv.Client()
		o.metadataCache = NewMetadataCacheWithLogger(nil, NewLogger("error"))
	})
}

func TestMetadataDiscovery_StatusRetryClassification(t *testing.T) {
	cases := []struct {
		name      string
		cfg       RetryConfig
		status    int
		wantCalls int32
	}{
		{"discovery 404 is a routing race and is retried", MetadataFetchRetryConfig(), http.StatusNotFound, 3},
		{"discovery 502 is retried", MetadataFetchRetryConfig(), http.StatusBadGateway, 3},
		{"discovery 503 is retried", MetadataFetchRetryConfig(), http.StatusServiceUnavailable, 3},
		{"discovery 429 is retried", MetadataFetchRetryConfig(), http.StatusTooManyRequests, 3},
		{"discovery 400 is terminal", MetadataFetchRetryConfig(), http.StatusBadRequest, 1},
		{"discovery 401 is terminal", MetadataFetchRetryConfig(), http.StatusUnauthorized, 1},
		{"discovery 403 is terminal", MetadataFetchRetryConfig(), http.StatusForbidden, 1},
		{"other configs keep 404 terminal", DefaultRetryConfig(), http.StatusNotFound, 1},
		{"other configs retry 502", DefaultRetryConfig(), http.StatusBadGateway, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, providerURL, hits := newFlakyDiscovery(t, c.status, 1<<20)
			mc := NewMetadataCacheWithLogger(nil, NewLogger("error"))
			re := NewRetryExecutor(fastRetry(c.cfg, 3), NewLogger("error"))

			err := re.ExecuteWithContext(context.Background(), func() error {
				_, fetchErr := mc.GetProviderMetadata(context.Background(), providerURL, srv.Client())
				return fetchErr
			})
			require.Error(t, err)
			assert.Equal(t, c.wantCalls, hits.Load())
		})
	}
}

func TestGetProviderMetadata_NonOKStatusIsHTTPError(t *testing.T) {
	srv, providerURL, _ := newFlakyDiscovery(t, http.StatusBadGateway, 1)
	mc := NewMetadataCacheWithLogger(nil, NewLogger("error"))

	_, err := mc.GetProviderMetadata(context.Background(), providerURL, srv.Client())
	require.Error(t, err)
	httpErr, ok := asHTTPError(err)
	require.True(t, ok, "a non-200 discovery response must carry its status: %v", err)
	assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
	assert.Contains(t, err.Error(), "HTTP 502")
}

func TestGetMetadataWithRecovery_RetriesStartupNotFound(t *testing.T) {
	srv, providerURL, hits := newFlakyDiscovery(t, http.StatusNotFound, 2)
	mc := NewMetadataCacheWithLogger(nil, NewLogger("error"))

	metadata, err := mc.GetMetadataWithRecovery(context.Background(), providerURL, srv.Client(), NewLogger("error"), nil)
	require.NoError(t, err)
	assert.Equal(t, srv.URL, metadata.Issuer)
	assert.Equal(t, int32(3), hits.Load())
}

func TestGetMetadataWithRecovery_StopsWhenContextEnds(t *testing.T) {
	srv, providerURL, _ := newFlakyDiscovery(t, http.StatusNotFound, 1<<20)
	mc := NewMetadataCacheWithLogger(nil, NewLogger("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := mc.GetMetadataWithRecovery(ctx, providerURL, srv.Client(), NewLogger("error"), nil)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "a canceled context must end the startup retries")
}

func TestRunMetadataInit_RecoversInBackgroundWithoutRequest(t *testing.T) {
	srv, providerURL, hits := newFlakyDiscovery(t, http.StatusNotFound, 3)
	oidc := newRecoveryTestOIDC(t, srv, providerURL)

	done := make(chan struct{})
	go func() {
		oidc.runMetadataInit(providerURL, fastRetry(metadataRecoveryBackoff(), 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background recovery did not finish")
	}

	select {
	case <-oidc.initComplete:
	default:
		t.Fatal("initComplete must be closed after the first failed attempt")
	}
	assert.True(t, oidc.metadataReady())
	assert.Equal(t, srv.URL, oidc.issuerURL)
	assert.Equal(t, int32(4), hits.Load(), "one startup attempt, two failed background attempts, one success")
}

func TestRunMetadataInit_OpensTheGateBeforeBackgroundRetries(t *testing.T) {
	srv, providerURL, hits := newFlakyDiscovery(t, http.StatusNotFound, 1<<20)
	oidc := newRecoveryTestOIDC(t, srv, providerURL)
	ctx, cancel := context.WithCancel(context.Background())
	oidc.ctx = ctx

	done := make(chan struct{})
	go func() {
		oidc.runMetadataInit(providerURL, fastRetry(metadataRecoveryBackoff(), 0))
		close(done)
	}()

	select {
	case <-oidc.initComplete:
	case <-time.After(5 * time.Second):
		t.Fatal("requests must not wait on initComplete while recovery retries")
	}
	require.Eventually(t, func() bool { return hits.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
	assert.False(t, oidc.metadataReady())

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background recovery must stop when the instance context ends")
	}
}

func TestRecoverMetadataInBackground_StopsOnCancelDuringDelay(t *testing.T) {
	srv, providerURL, hits := newFlakyDiscovery(t, http.StatusNotFound, 1<<20)
	oidc := newRecoveryTestOIDC(t, srv, providerURL)
	ctx, cancel := context.WithCancel(context.Background())
	oidc.ctx = ctx

	backoff := metadataRecoveryBackoff()
	backoff.InitialDelay = time.Hour
	done := make(chan struct{})
	go func() {
		oidc.recoverMetadataInBackground(providerURL, backoff)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background recovery must stop when the instance context ends")
	}
	assert.Zero(t, hits.Load())
}

func TestRecoverMetadataInBackground_SkipsWhenAlreadyRecovered(t *testing.T) {
	srv, providerURL, hits := newFlakyDiscovery(t, http.StatusNotFound, 1<<20)
	oidc := newRecoveryTestOIDC(t, srv, providerURL)
	oidc.issuerURL = srv.URL // the request path recovered it first

	oidc.recoverMetadataInBackground(providerURL, fastRetry(metadataRecoveryBackoff(), 0))
	assert.Zero(t, hits.Load())
}

func TestServeHTTP_MetadataUnavailableSetsRetryAfter(t *testing.T) {
	oidc := newTestOIDC(t, func(o *TraefikOidc) { o.issuerURL = "" })
	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	oidc.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, metadataUnavailableRetryAfter, rec.Header().Get("Retry-After"))
	assert.True(t, strings.Contains(rec.Body.String(), "metadata"))
}

func TestMetadataRecoveryLogLoud(t *testing.T) {
	cases := []struct {
		attempt int
		want    bool
	}{
		{1, true}, {3, true}, {4, false}, {9, false}, {10, true}, {11, false}, {20, true},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, metadataRecoveryLogLoud(c.attempt), "attempt %d", c.attempt)
	}
}

func TestRecoverMetadataInBackground_KeepsRetryingWithoutIssuer(t *testing.T) {
	hits := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProviderMetadata{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	providerURL := srv.URL + "/" + t.Name()
	oidc := newRecoveryTestOIDC(t, srv, providerURL)
	ctx, cancel := context.WithCancel(context.Background())
	oidc.ctx = ctx

	done := make(chan struct{})
	go func() {
		oidc.recoverMetadataInBackground(providerURL, fastRetry(metadataRecoveryBackoff(), 0))
		close(done)
	}()
	require.Eventually(t, func() bool { return hits.Load() >= 1 }, 5*time.Second, time.Millisecond)

	select {
	case <-done:
		t.Fatal("a document without an issuer must not end recovery")
	case <-time.After(100 * time.Millisecond):
	}
	assert.False(t, oidc.metadataReady())

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background recovery must stop when the instance context ends")
	}
}

func TestNew_CloseStopsStartupRetries(t *testing.T) {
	if testing.Short() {
		t.Skip("drives New through the real startup retry delays")
	}
	srv, _, hits := newFlakyDiscovery(t, http.StatusNotFound, 1<<20)
	config := &Config{
		ProviderURL:          srv.URL,
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "test-encryption-key-thats-long-enough",
		RateLimit:            100,
	}
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), config, "issue147-close")
	require.NoError(t, err)
	m, ok := handler.(*TraefikOidc)
	require.True(t, ok)

	// The first retry delay is 1s, so a second request proves the retries run.
	require.Eventually(t, func() bool { return hits.Load() >= 2 }, 10*time.Second, 10*time.Millisecond)

	start := time.Now()
	require.NoError(t, m.Close())
	assert.Less(t, time.Since(start), 5*time.Second, "Close must not wait for the startup retries")

	stopped := hits.Load()
	time.Sleep(2 * time.Second)
	assert.Equal(t, stopped, hits.Load(), "no discovery request may follow Close")
}
