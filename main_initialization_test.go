package traefikoidc

import (
	"container/list"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestInitializeMetadata tests the initializeMetadata function
func TestInitializeMetadata(t *testing.T) {
	tests := []struct {
		setupMock    func() *httptest.Server
		validateFunc func(*testing.T, *TraefikOidc)
		name         string
		providerURL  string
		wantPanic    bool
	}{
		{
			name:        "successful metadata initialization",
			providerURL: "",
			setupMock: func() *httptest.Server {
				// Issuer must share the host with providerURL (the httptest
				// server), otherwise the discovery doc is rejected as poisoned
				// (audit ranks 21/22). Real providers keep issuer + endpoints on
				// the same host, so derive them all from the server URL.
				var srv *httptest.Server
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(ProviderMetadata{
							Issuer:        srv.URL,
							AuthURL:       srv.URL + "/auth",
							TokenURL:      srv.URL + "/token",
							JWKSURL:       srv.URL + "/jwks",
							RevokeURL:     srv.URL + "/revoke",
							EndSessionURL: srv.URL + "/logout",
						})
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				return srv
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				if oidc.authURL == "" || !strings.HasSuffix(oidc.authURL, "/auth") {
					t.Errorf("expected authURL to be set, got %s", oidc.authURL)
				}
				if oidc.tokenURL == "" || !strings.HasSuffix(oidc.tokenURL, "/token") {
					t.Errorf("expected tokenURL to be set, got %s", oidc.tokenURL)
				}
				if oidc.jwksURL == "" || !strings.HasSuffix(oidc.jwksURL, "/jwks") {
					t.Errorf("expected jwksURL to be set, got %s", oidc.jwksURL)
				}
				if oidc.revocationURL == "" || !strings.HasSuffix(oidc.revocationURL, "/revoke") {
					t.Errorf("expected revocationURL to be set, got %s", oidc.revocationURL)
				}
				if oidc.endSessionURL == "" || !strings.HasSuffix(oidc.endSessionURL, "/logout") {
					t.Errorf("expected endSessionURL to be set, got %s", oidc.endSessionURL)
				}
				if oidc.issuerURL == "" {
					t.Errorf("expected issuerURL to be pinned to provider host, got empty")
				}
			},
			wantPanic: false,
		},
		{
			name:        "metadata endpoint returns 404",
			providerURL: "",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte("Not Found"))
				}))
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				// URLs should remain unchanged when metadata fetch fails
				if oidc.authURL != "" {
					t.Logf("authURL remained as: %s", oidc.authURL)
				}
			},
			wantPanic: false,
		},
		{
			name:        "metadata endpoint returns malformed JSON",
			providerURL: "",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(`{"issuer": "test", invalid json`))
					}
				}))
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				// URLs should remain unchanged when JSON parsing fails
				if oidc.tokenURL != "" {
					t.Logf("tokenURL remained as: %s", oidc.tokenURL)
				}
			},
			wantPanic: false,
		},
		{
			name:        "metadata endpoint times out",
			providerURL: "",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate timeout by sleeping longer than client timeout
					time.Sleep(2 * time.Second)
				}))
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				// URLs should remain unchanged when request times out
				t.Log("Metadata fetch timed out as expected")
			},
			wantPanic: false,
		},
		{
			name:        "partial metadata response",
			providerURL: "",
			setupMock: func() *httptest.Server {
				// Issuer host must match providerURL (audit ranks 21/22).
				var srv *httptest.Server
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
						w.Header().Set("Content-Type", "application/json")
						// Only return some fields
						json.NewEncoder(w).Encode(map[string]string{
							"issuer":                 srv.URL,
							"authorization_endpoint": srv.URL + "/auth",
							"token_endpoint":         srv.URL + "/token",
							// Missing jwks_uri, revocation_endpoint, end_session_endpoint
						})
					}
				}))
				return srv
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				if oidc.authURL == "" || !strings.HasSuffix(oidc.authURL, "/auth") {
					t.Errorf("expected authURL to be set, got %s", oidc.authURL)
				}
				if oidc.tokenURL == "" || !strings.HasSuffix(oidc.tokenURL, "/token") {
					t.Errorf("expected tokenURL to be set, got %s", oidc.tokenURL)
				}
				// JWKS URL and others may be empty
				if oidc.jwksURL != "" {
					t.Logf("jwksURL: %s", oidc.jwksURL)
				}
			},
			wantPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			server := tt.setupMock()
			defer server.Close()

			// Create TraefikOidc instance with minimal setup
			oidc := &TraefikOidc{
				providerURL: server.URL,
				httpClient: &http.Client{
					Timeout: 1 * time.Second,
				},
				logger:       NewLogger("debug"),
				initComplete: make(chan struct{}),
				metadataCache: &MetadataCache{
					cache: &UniversalCache{
						items:   make(map[string]*CacheItem),
						lruList: list.New(),
						config: UniversalCacheConfig{
							DefaultTTL: 3600 * time.Second,
							MaxSize:    100,
						},
						logger: NewLogger("debug"),
					},
					logger: NewLogger("debug"),
				},
			}

			// Handle potential panics
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("expected panic but got none")
					}
				}()
			}

			// Initialize metadata
			oidc.initializeMetadata(server.URL)

			// Validate results
			if tt.validateFunc != nil {
				tt.validateFunc(t, oidc)
			}
		})
	}
}

// TestInitializeMetadata_Concurrency tests concurrent metadata initialization
func TestInitializeMetadata_Concurrency(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			// Issuer host must match providerURL (audit ranks 21/22).
			json.NewEncoder(w).Encode(ProviderMetadata{
				Issuer:        server.URL,
				AuthURL:       server.URL + "/auth",
				TokenURL:      server.URL + "/token",
				JWKSURL:       server.URL + "/jwks",
				RevokeURL:     server.URL + "/revoke",
				EndSessionURL: server.URL + "/logout",
			})
		}
	}))
	defer server.Close()

	// Create multiple TraefikOidc instances
	const numInstances = 5
	var wg sync.WaitGroup
	wg.Add(numInstances)

	for i := 0; i < numInstances; i++ {
		go func() {
			defer wg.Done()

			oidc := &TraefikOidc{
				providerURL: server.URL,
				httpClient: &http.Client{
					Timeout: 5 * time.Second,
				},
				logger:       NewLogger("debug"),
				initComplete: make(chan struct{}),
				metadataCache: &MetadataCache{
					cache: &UniversalCache{
						items:   make(map[string]*CacheItem),
						lruList: list.New(),
						config: UniversalCacheConfig{
							DefaultTTL: 3600 * time.Second,
							MaxSize:    100,
						},
						logger: NewLogger("debug"),
					},
					logger: NewLogger("debug"),
				},
			}

			oidc.initializeMetadata(server.URL)

			// Verify initialization
			if oidc.tokenURL == "" || !strings.HasSuffix(oidc.tokenURL, "/token") {
				t.Errorf("expected tokenURL to be set")
			}
		}()
	}

	wg.Wait()

	// Check that multiple requests were made
	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	if finalCount != numInstances {
		t.Logf("Made %d requests for %d instances (some may have been cached)", finalCount, numInstances)
	}
}

// TestProviderDetection tests provider-specific detection functions
func TestProviderDetection(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
		isGoogle  bool
		isAzure   bool
	}{
		{
			name:      "Google provider",
			issuerURL: "https://accounts.google.com",
			isGoogle:  true,
			isAzure:   false,
		},
		{
			name:      "Google provider with different URL",
			issuerURL: "https://google.com/oauth",
			isGoogle:  true,
			isAzure:   false,
		},
		{
			name:      "Azure AD provider",
			issuerURL: "https://login.microsoftonline.com/tenant",
			isGoogle:  false,
			isAzure:   true,
		},
		{
			name:      "Azure AD with sts.windows.net",
			issuerURL: "https://sts.windows.net/tenant",
			isGoogle:  false,
			isAzure:   true,
		},
		{
			name:      "Azure AD with login.windows.net",
			issuerURL: "https://login.windows.net/tenant",
			isGoogle:  false,
			isAzure:   true,
		},
		{
			name:      "Generic provider",
			issuerURL: "https://auth.example.com",
			isGoogle:  false,
			isAzure:   false,
		},
		{
			name:      "Empty issuer URL",
			issuerURL: "",
			isGoogle:  false,
			isAzure:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidc := &TraefikOidc{
				issuerURL: tt.issuerURL,
			}

			gotGoogle := oidc.isGoogleProvider()
			if gotGoogle != tt.isGoogle {
				t.Errorf("isGoogleProvider() = %v, want %v", gotGoogle, tt.isGoogle)
			}

			gotAzure := oidc.isAzureProvider()
			if gotAzure != tt.isAzure {
				t.Errorf("isAzureProvider() = %v, want %v", gotAzure, tt.isAzure)
			}
		})
	}
}

// TestInitializationWaiting tests waiting for initialization to complete
func TestInitializationWaiting(t *testing.T) {
	t.Run("wait for initialization completion", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay response to simulate slow initialization
			time.Sleep(100 * time.Millisecond)

			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				// Issuer host must match providerURL (audit ranks 21/22).
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   server.URL,
					AuthURL:  server.URL + "/auth",
					TokenURL: server.URL + "/token",
					JWKSURL:  server.URL + "/jwks",
				})
			}
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			providerURL: server.URL,
			httpClient: &http.Client{
				Timeout: 5 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
			metadataCache: &MetadataCache{
				cache: &UniversalCache{
					items:   make(map[string]*CacheItem),
					lruList: list.New(),
					config: UniversalCacheConfig{
						DefaultTTL: 3600 * time.Second,
						MaxSize:    100,
					},
					logger: NewLogger("debug"),
				},
				logger: NewLogger("debug"),
			},
		}

		// Start initialization in background
		go func() {
			oidc.initializeMetadata(server.URL)
			// initComplete is closed internally by initializeMetadata
		}()

		// Wait for initialization
		select {
		case <-oidc.initComplete:
			// Success
			if oidc.tokenURL == "" || !strings.HasSuffix(oidc.tokenURL, "/token") {
				t.Error("expected tokenURL to be set after initialization")
			}
		case <-time.After(2 * time.Second):
			t.Error("initialization did not complete in time")
		}
	})

	t.Run("multiple waiters for initialization", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay to ensure multiple waiters
			time.Sleep(50 * time.Millisecond)

			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				// Issuer host must match providerURL (audit ranks 21/22).
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   server.URL,
					AuthURL:  server.URL + "/auth",
					TokenURL: server.URL + "/token",
					JWKSURL:  server.URL + "/jwks",
				})
			}
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			providerURL: server.URL,
			httpClient: &http.Client{
				Timeout: 5 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
			metadataCache: &MetadataCache{
				cache: &UniversalCache{
					items:   make(map[string]*CacheItem),
					lruList: list.New(),
					config: UniversalCacheConfig{
						DefaultTTL: 3600 * time.Second,
						MaxSize:    100,
					},
					logger: NewLogger("debug"),
				},
				logger: NewLogger("debug"),
			},
		}

		// Start initialization
		go func() {
			oidc.initializeMetadata(server.URL)
			// initComplete is closed internally by initializeMetadata
		}()

		// Create multiple waiters
		const numWaiters = 5
		var wg sync.WaitGroup
		wg.Add(numWaiters)

		for i := 0; i < numWaiters; i++ {
			go func(id int) {
				defer wg.Done()

				select {
				case <-oidc.initComplete:
					// All waiters should see the same initialized state
					if oidc.tokenURL == "" || !strings.HasSuffix(oidc.tokenURL, "/token") {
						t.Errorf("waiter %d: expected tokenURL to be set", id)
					}
				case <-time.After(2 * time.Second):
					t.Errorf("waiter %d: timeout waiting for initialization", id)
				}
			}(i)
		}

		wg.Wait()
	})
}

// TestFirstRequestHandling tests the first request initialization behavior
func TestFirstRequestHandling(t *testing.T) {
	t.Run("first request triggers initialization", func(t *testing.T) {
		initCalled := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				initCalled = true
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   "https://first.example.com",
					AuthURL:  "https://first.example.com/auth",
					TokenURL: "https://first.example.com/token",
					JWKSURL:  "https://first.example.com/jwks",
				})
			}
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			providerURL:         server.URL,
			firstRequestStarted: 0,
			httpClient: &http.Client{
				Timeout: 5 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
			ctx:          context.Background(),
			cancelFunc:   func() {},
			metadataCache: &MetadataCache{
				cache: &UniversalCache{
					items:   make(map[string]*CacheItem),
					lruList: list.New(),
					config: UniversalCacheConfig{
						DefaultTTL: 3600 * time.Second,
						MaxSize:    100,
					},
					logger: NewLogger("debug"),
				},
				logger: NewLogger("debug"),
			},
		}

		// Simulate first request processing — single-firing via CAS.
		if atomic.CompareAndSwapInt32(&oidc.firstRequestStarted, 0, 1) {
			// This would normally be called asynchronously
			go func() {
				oidc.initializeMetadata(server.URL)
				// initComplete is closed internally by initializeMetadata
			}()
		}

		// Wait for initialization
		select {
		case <-oidc.initComplete:
			if !initCalled {
				t.Error("expected metadata endpoint to be called")
			}
		case <-time.After(2 * time.Second):
			t.Error("initialization timeout")
		}
	})

	t.Run("concurrent first requests handled correctly", func(t *testing.T) {
		metadataCallCount := 0
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				mu.Lock()
				metadataCallCount++
				mu.Unlock()

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   "https://concurrent.example.com",
					AuthURL:  "https://concurrent.example.com/auth",
					TokenURL: "https://concurrent.example.com/token",
					JWKSURL:  "https://concurrent.example.com/jwks",
				})
			}
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			providerURL:         server.URL,
			firstRequestStarted: 0,
			httpClient: &http.Client{
				Timeout: 5 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
			ctx:          context.Background(),
			cancelFunc:   func() {},
			metadataCache: &MetadataCache{
				cache: &UniversalCache{
					items:   make(map[string]*CacheItem),
					lruList: list.New(),
					config: UniversalCacheConfig{
						DefaultTTL: 3600 * time.Second,
						MaxSize:    100,
					},
					logger: NewLogger("debug"),
				},
				logger: NewLogger("debug"),
			},
		}

		// Simulate multiple concurrent "first" requests — only one CAS winner
		// fires the bootstrap path.
		const numRequests = 10
		var wg sync.WaitGroup
		wg.Add(numRequests)

		var initStarted int32

		for i := 0; i < numRequests; i++ {
			go func() {
				defer wg.Done()

				if atomic.CompareAndSwapInt32(&oidc.firstRequestStarted, 0, 1) {
					atomic.AddInt32(&initStarted, 1)
					// Only one should actually start initialization
					oidc.initializeMetadata(server.URL)
				}
			}()
		}

		wg.Wait()

		// Verify only one initialization was started
		if atomic.LoadInt32(&initStarted) != 1 {
			t.Errorf("expected exactly 1 initialization, got %d", atomic.LoadInt32(&initStarted))
		}

		// The metadata endpoint might be called once or not at all depending on timing
		mu.Lock()
		finalCount := metadataCallCount
		mu.Unlock()

		if finalCount > 1 {
			t.Errorf("metadata endpoint called %d times, expected at most 1", finalCount)
		}
	})
}
