package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCreateProxy tests the CreateProxy method
func TestCreateProxy(t *testing.T) {
	factory := NewFactory(nil)
	client, err := factory.CreateProxy()
	if err != nil {
		t.Fatalf("Failed to create proxy client: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil proxy client")
	}

	// Verify proxy configuration specifics
	if client.Timeout != 60*time.Second {
		t.Errorf("Expected proxy timeout to be 60s, got %v", client.Timeout)
	}
}

// TestValidateConfigEdgeCases tests additional validation scenarios
func TestValidateConfigEdgeCases(t *testing.T) {
	factory := NewFactory(nil)

	testCases := []struct {
		name       string
		config     Config
		shouldFail bool
		errorMsg   string
	}{
		{
			name: "Negative MaxIdleConnsPerHost",
			config: Config{
				MaxIdleConnsPerHost: -1,
			},
			shouldFail: true,
			errorMsg:   "MaxIdleConnsPerHost cannot be negative",
		},
		{
			name: "Excessive MaxIdleConnsPerHost",
			config: Config{
				MaxIdleConnsPerHost: 200,
			},
			shouldFail: true,
			errorMsg:   "MaxIdleConnsPerHost too high",
		},
		{
			name: "Negative MaxConnsPerHost",
			config: Config{
				MaxConnsPerHost: -1,
			},
			shouldFail: true,
			errorMsg:   "MaxConnsPerHost cannot be negative",
		},
		{
			name: "Excessive MaxConnsPerHost",
			config: Config{
				MaxConnsPerHost: 300,
			},
			shouldFail: true,
			errorMsg:   "MaxConnsPerHost too high",
		},
		{
			name: "Negative WriteBufferSize",
			config: Config{
				WriteBufferSize: -1,
			},
			shouldFail: true,
			errorMsg:   "buffer sizes cannot be negative",
		},
		{
			name: "Negative ReadBufferSize",
			config: Config{
				ReadBufferSize: -1,
			},
			shouldFail: true,
			errorMsg:   "buffer sizes cannot be negative",
		},
		{
			name: "Excessive WriteBufferSize",
			config: Config{
				WriteBufferSize: 2 * 1024 * 1024,
			},
			shouldFail: true,
			errorMsg:   "buffer sizes too large",
		},
		{
			name: "Excessive ReadBufferSize",
			config: Config{
				ReadBufferSize: 2 * 1024 * 1024,
			},
			shouldFail: true,
			errorMsg:   "buffer sizes too large",
		},
		{
			name: "Valid edge values",
			config: Config{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     200,
				Timeout:             5 * time.Minute,
				WriteBufferSize:     1024 * 1024,
				ReadBufferSize:      1024 * 1024,
			},
			shouldFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := factory.ValidateConfig(&tc.config)
			if tc.shouldFail {
				if err == nil {
					t.Fatalf("Expected validation to fail with message containing: %s", tc.errorMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

// TestTransportPoolClose tests the Close method of TransportPool
func TestTransportPoolClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		ctx:         ctx,
		cancel:      cancel,
		clientCount: 0,
		maxClients:  5,
	}

	// Create some transports
	config := PresetConfigs[ClientTypeDefault]
	transport1 := pool.GetOrCreateTransport(config)
	if transport1 == nil {
		t.Fatal("Failed to create transport")
	}

	// Modify config slightly to create a different transport
	config.Timeout = 20 * time.Second
	transport2 := pool.GetOrCreateTransport(config)
	if transport2 == nil {
		t.Fatal("Failed to create second transport")
	}

	// Verify transports were created
	pool.mu.RLock()
	initialCount := len(pool.transports)
	pool.mu.RUnlock()
	if initialCount == 0 {
		t.Fatal("Expected transports to be created")
	}

	// Close the pool
	err := pool.Close()
	if err != nil {
		t.Fatalf("Failed to close pool: %v", err)
	}

	// Verify all transports were removed
	pool.mu.RLock()
	finalCount := len(pool.transports)
	pool.mu.RUnlock()
	if finalCount != 0 {
		t.Fatalf("Expected 0 transports after close, got %d", finalCount)
	}

	// Verify client count was reset
	if pool.clientCount != 0 {
		t.Fatalf("Expected client count to be 0 after close, got %d", pool.clientCount)
	}
}

// TestNoOpLogger tests the no-op logger implementation
func TestNoOpLogger(t *testing.T) {
	logger := &noOpLogger{}

	// These should not panic or cause any issues
	logger.Debug("test debug")
	logger.Debugf("test debug %s", "formatted")
	logger.Info("test info")
	logger.Infof("test info %s", "formatted")
	logger.Error("test error")
	logger.Errorf("test error %s", "formatted")

	// Test using logger with factory
	factory := NewFactory(logger)
	client, err := factory.CreateDefault()
	if err != nil {
		t.Fatalf("Failed to create client with no-op logger: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// TestCreateClientWithCustomTLS tests creating client with custom TLS config
func TestCreateClientWithCustomTLS(t *testing.T) {
	factory := NewFactory(nil)

	customTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	config := Config{
		Timeout:             10 * time.Second,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     5,
		TLSConfig:           customTLS,
	}

	client, err := factory.CreateClient(config)
	if err != nil {
		t.Fatalf("Failed to create client with custom TLS: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// TestCreateClientWithMaxRedirects tests redirect limiting
func TestCreateClientWithMaxRedirects(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		if redirectCount <= 3 {
			http.Redirect(w, r, "/redirect", http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("final"))
		}
	}))
	defer server.Close()

	factory := NewFactory(nil)

	// Test with max redirects = 2 (should fail)
	config := Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        2,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     5,
	}

	client, err := factory.CreateClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	redirectCount = 0
	_, err = client.Get(server.URL)
	if err == nil {
		t.Fatal("Expected redirect limit error")
	}

	// Test with max redirects = 5 (should succeed)
	config.MaxRedirects = 5
	client, err = factory.CreateClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	redirectCount = 0
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestTransportPoolMaxClientsLimit tests the max clients limitation
func TestTransportPoolMaxClientsLimit(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		clientCount: 0,
		maxClients:  2, // Set low limit for testing
	}

	// Create transports up to the limit
	configs := []Config{
		{Timeout: 10 * time.Second},
		{Timeout: 20 * time.Second},
		{Timeout: 30 * time.Second}, // This should not create a new transport
	}

	var transports []*http.Transport
	for i, config := range configs {
		transport := pool.GetOrCreateTransport(config)
		if i < 2 {
			if transport == nil {
				t.Fatalf("Expected transport %d to be created", i)
			}
			transports = append(transports, transport)
		} else {
			// When limit is reached, should return existing transport or nil
			if transport == nil {
				// This is acceptable - nil when limit reached
				t.Log("Transport creation blocked due to client limit")
			}
		}
	}

	// Verify client count doesn't exceed limit
	if pool.clientCount > pool.maxClients {
		t.Fatalf("Client count %d exceeds max %d", pool.clientCount, pool.maxClients)
	}
}

// TestCleanupIdleTransportsContext tests cleanup goroutine with context
func TestCleanupIdleTransportsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		ctx:         ctx,
		cancel:      cancel,
		clientCount: 0,
		maxClients:  5,
	}

	// Start cleanup goroutine
	done := make(chan bool)
	go func() {
		pool.cleanupIdleTransports(ctx)
		done <- true
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel context to stop cleanup
	cancel()

	// Wait for goroutine to exit
	select {
	case <-done:
		// Success - goroutine exited
	case <-time.After(1 * time.Second):
		t.Fatal("Cleanup goroutine did not exit after context cancellation")
	}
}

// TestFactoryWithLogger tests factory creation with custom logger
func TestFactoryWithLogger(t *testing.T) {
	// Create a mock logger that implements the Logger interface
	logger := &MockLogger{}

	factory := NewFactory(logger)
	if factory.logger == nil {
		t.Fatal("Expected logger to be set")
	}
}

// MockLogger for testing
type MockLogger struct {
	debugCalled  bool
	debugfCalled bool
	infoCalled   bool
	infofCalled  bool
	errorCalled  bool
	errorfCalled bool
}

func (m *MockLogger) Debug(msg string)                          { m.debugCalled = true }
func (m *MockLogger) Debugf(format string, args ...interface{}) { m.debugfCalled = true }
func (m *MockLogger) Info(msg string)                           { m.infoCalled = true }
func (m *MockLogger) Infof(format string, args ...interface{})  { m.infofCalled = true }
func (m *MockLogger) Error(msg string)                          { m.errorCalled = true }
func (m *MockLogger) Errorf(format string, args ...interface{}) { m.errorfCalled = true }

// TestCreateClientLogging tests that logger is called during client creation
func TestCreateClientLogging(t *testing.T) {
	logger := &MockLogger{}
	factory := NewFactory(logger)

	client, err := factory.CreateDefault()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Verify logger was called
	if !logger.debugfCalled {
		t.Error("Expected Debugf to be called during client creation")
	}
}
