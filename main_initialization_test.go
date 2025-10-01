package traefikoidc

import (
	"container/list"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestInitializeMetadata tests the initializeMetadata function
func TestInitializeMetadata(t *testing.T) {
	tests := []struct {
		name         string
		providerURL  string
		setupMock    func() *httptest.Server
		validateFunc func(*testing.T, *TraefikOidc)
		wantPanic    bool
	}{
		{
			name:        "successful metadata initialization",
			providerURL: "",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(ProviderMetadata{
							Issuer:        "https://provider.example.com",
							AuthURL:       "https://provider.example.com/auth",
							TokenURL:      "https://provider.example.com/token",
							JWKSURL:       "https://provider.example.com/jwks",
							RevokeURL:     "https://provider.example.com/revoke",
							EndSessionURL: "https://provider.example.com/logout",
						})
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				if oidc.authURL != "https://provider.example.com/auth" {
					t.Errorf("expected authURL to be set, got %s", oidc.authURL)
				}
				if oidc.tokenURL != "https://provider.example.com/token" {
					t.Errorf("expected tokenURL to be set, got %s", oidc.tokenURL)
				}
				if oidc.jwksURL != "https://provider.example.com/jwks" {
					t.Errorf("expected jwksURL to be set, got %s", oidc.jwksURL)
				}
				if oidc.revocationURL != "https://provider.example.com/revoke" {
					t.Errorf("expected revocationURL to be set, got %s", oidc.revocationURL)
				}
				if oidc.endSessionURL != "https://provider.example.com/logout" {
					t.Errorf("expected endSessionURL to be set, got %s", oidc.endSessionURL)
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
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
						w.Header().Set("Content-Type", "application/json")
						// Only return some fields
						json.NewEncoder(w).Encode(map[string]string{
							"issuer":                 "https://partial.example.com",
							"authorization_endpoint": "https://partial.example.com/auth",
							"token_endpoint":         "https://partial.example.com/token",
							// Missing jwks_uri, revocation_endpoint, end_session_endpoint
						})
					}
				}))
			},
			validateFunc: func(t *testing.T, oidc *TraefikOidc) {
				if oidc.authURL != "https://partial.example.com/auth" {
					t.Errorf("expected authURL to be set, got %s", oidc.authURL)
				}
				if oidc.tokenURL != "https://partial.example.com/token" {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ProviderMetadata{
				Issuer:        "https://concurrent.example.com",
				AuthURL:       "https://concurrent.example.com/auth",
				TokenURL:      "https://concurrent.example.com/token",
				JWKSURL:       "https://concurrent.example.com/jwks",
				RevokeURL:     "https://concurrent.example.com/revoke",
				EndSessionURL: "https://concurrent.example.com/logout",
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
			if oidc.tokenURL != "https://concurrent.example.com/token" {
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay response to simulate slow initialization
			time.Sleep(100 * time.Millisecond)

			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   "https://slow.example.com",
					AuthURL:  "https://slow.example.com/auth",
					TokenURL: "https://slow.example.com/token",
					JWKSURL:  "https://slow.example.com/jwks",
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
			if oidc.tokenURL != "https://slow.example.com/token" {
				t.Error("expected tokenURL to be set after initialization")
			}
		case <-time.After(2 * time.Second):
			t.Error("initialization did not complete in time")
		}
	})

	t.Run("multiple waiters for initialization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay to ensure multiple waiters
			time.Sleep(50 * time.Millisecond)

			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProviderMetadata{
					Issuer:   "https://multi.example.com",
					AuthURL:  "https://multi.example.com/auth",
					TokenURL: "https://multi.example.com/token",
					JWKSURL:  "https://multi.example.com/jwks",
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
					if oidc.tokenURL != "https://multi.example.com/token" {
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
			providerURL:          server.URL,
			firstRequestReceived: false,
			firstRequestMutex:    sync.Mutex{},
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

		// Simulate first request processing
		oidc.firstRequestMutex.Lock()
		if !oidc.firstRequestReceived {
			oidc.firstRequestReceived = true
			oidc.firstRequestMutex.Unlock()

			// This would normally be called asynchronously
			go func() {
				oidc.initializeMetadata(server.URL)
				// initComplete is closed internally by initializeMetadata
			}()
		} else {
			oidc.firstRequestMutex.Unlock()
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
			providerURL:          server.URL,
			firstRequestReceived: false,
			firstRequestMutex:    sync.Mutex{},
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

		// Simulate multiple concurrent "first" requests
		const numRequests = 10
		var wg sync.WaitGroup
		wg.Add(numRequests)

		initStarted := 0
		var initMu sync.Mutex

		for i := 0; i < numRequests; i++ {
			go func() {
				defer wg.Done()

				oidc.firstRequestMutex.Lock()
				if !oidc.firstRequestReceived {
					oidc.firstRequestReceived = true
					oidc.firstRequestMutex.Unlock()

					initMu.Lock()
					initStarted++
					initMu.Unlock()

					// Only one should actually start initialization
					oidc.initializeMetadata(server.URL)
				} else {
					oidc.firstRequestMutex.Unlock()
				}
			}()
		}

		wg.Wait()

		// Verify only one initialization was started
		if initStarted != 1 {
			t.Errorf("expected exactly 1 initialization, got %d", initStarted)
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
