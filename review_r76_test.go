package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	"testing"
	"time"
)

// TestDCR_ConcurrentGate_RegistersOnce regresses the data race and double
// dynamic client registration when the init goroutine and the metadata
// refresh goroutine both evaluate the DCR gate concurrently. The dcrMu guard
// must allow exactly one RegistrationRequest.
func TestDCR_ConcurrentGate_RegistersOnce(t *testing.T) {
	var mu sync.Mutex
	var regs int
	entered := make(chan struct{})
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		regs++
		mu.Unlock()
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"client_id":"reg-client","client_secret":"s","client_secret_expires_at":0}`)
	}))
	defer srv.Close()

	logger := NewLogger("error")
	dcr := &DynamicClientRegistrationConfig{Enabled: true, RegistrationEndpoint: srv.URL, ClientMetadata: &ClientRegistrationMetadata{RedirectURIs: []string{"https://app.example.com/callback"}}}
	oidc := &TraefikOidc{
		logger:                 logger,
		providerURL:            "https://provider.example.com",
		dcrConfig:              dcr,
		ctx:                    context.Background(),
		httpClient:             srv.Client(),
		dynamicClientRegistrar: NewDynamicClientRegistrar(srv.Client(), logger, dcr, "https://provider.example.com"),
	}

	md := &ProviderMetadata{
		Issuer:          "https://provider.example.com",
		AuthURL:         "https://provider.example.com/auth",
		TokenURL:        "https://provider.example.com/token",
		JWKSURL:         "https://provider.example.com/jwks",
		RegistrationURL: srv.URL,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); oidc.updateMetadataEndpoints(md) }()

	// Wait until the first registration has reached the server (and is
	// blocked), then let a second goroutine evaluate the gate concurrently.
	<-entered

	wg.Add(1)
	go func() { defer wg.Done(); oidc.updateMetadataEndpoints(md) }()

	// On the unfixed code the second goroutine sees clientID=="" and
	// registers a second client; on the fix it blocks on dcrMu and skips.
	time.Sleep(500 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	n := regs
	mu.Unlock()
	if n != 1 {
		t.Fatalf("want exactly 1 client registration under concurrent gate eval, got %d", n)
	}
}
