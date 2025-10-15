package middleware

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	DebugCalls  []string
	DebugfCalls []string
	ErrorCalls  []string
	ErrorfCalls []string
	InfoCalls   []string
	InfofCalls  []string
}

func (m *MockLogger) Debug(msg string) {
	m.DebugCalls = append(m.DebugCalls, msg)
}

func (m *MockLogger) Debugf(format string, args ...interface{}) {
	m.DebugfCalls = append(m.DebugfCalls, format)
}

func (m *MockLogger) Error(msg string) {
	m.ErrorCalls = append(m.ErrorCalls, msg)
}

func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.ErrorfCalls = append(m.ErrorfCalls, format)
}

func (m *MockLogger) Info(msg string) {
	m.InfoCalls = append(m.InfoCalls, msg)
}

func (m *MockLogger) Infof(format string, args ...interface{}) {
	m.InfofCalls = append(m.InfofCalls, format)
}

// TestNewRequestProcessor tests the constructor
func TestNewRequestProcessor(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	if processor == nil {
		t.Error("Expected NewRequestProcessor to return non-nil processor")
		return
	}

	if processor.logger != logger {
		t.Error("Expected processor to use provided logger")
	}
}

// TestBuildRequestContext tests request context building
func TestBuildRequestContext(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name         string
		setupRequest func() (*http.Request, http.ResponseWriter)
		redirectPath string
		expectedURL  string
		expectedHost string
	}{
		{
			name: "Basic HTTP request",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				rw := httptest.NewRecorder()
				return req, rw
			},
			redirectPath: "/callback",
			expectedURL:  "http://example.com/callback",
			expectedHost: "example.com",
		},
		{
			name: "HTTPS request with TLS",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "https://secure.com/test", nil)
				req.TLS = &tls.ConnectionState{} // Simulate TLS
				rw := httptest.NewRecorder()
				return req, rw
			},
			redirectPath: "/auth",
			expectedURL:  "https://secure.com/auth",
			expectedHost: "secure.com",
		},
		{
			name: "Request with X-Forwarded-Proto header",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://internal.com/test", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				rw := httptest.NewRecorder()
				return req, rw
			},
			redirectPath: "/callback",
			expectedURL:  "https://internal.com/callback",
			expectedHost: "internal.com",
		},
		{
			name: "Request with X-Forwarded-Host header",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://internal.com/test", nil)
				req.Header.Set("X-Forwarded-Host", "public.com")
				rw := httptest.NewRecorder()
				return req, rw
			},
			redirectPath: "/callback",
			expectedURL:  "http://public.com/callback",
			expectedHost: "public.com",
		},
		{
			name: "Request with both forwarded headers",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://internal.com/test", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "public.com")
				rw := httptest.NewRecorder()
				return req, rw
			},
			redirectPath: "/auth",
			expectedURL:  "https://public.com/auth",
			expectedHost: "public.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, rw := tt.setupRequest()
			ctx := processor.BuildRequestContext(rw, req, tt.redirectPath)

			if ctx == nil {
				t.Error("Expected BuildRequestContext to return non-nil context")
				return
			}

			if ctx.Writer != rw {
				t.Error("Expected context writer to match provided writer")
			}

			if ctx.Request != req {
				t.Error("Expected context request to match provided request")
			}

			if ctx.RedirectURL != tt.expectedURL {
				t.Errorf("Expected redirect URL '%s', got '%s'", tt.expectedURL, ctx.RedirectURL)
			}

			if ctx.Host != tt.expectedHost {
				t.Errorf("Expected host '%s', got '%s'", tt.expectedHost, ctx.Host)
			}
		})
	}
}

// TestIsHealthCheckRequest tests health check detection
func TestIsHealthCheckRequest(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Health check path",
			path:     "/health",
			expected: true,
		},
		{
			name:     "Health check subpath",
			path:     "/health/status",
			expected: true,
		},
		{
			name:     "Health check with query params",
			path:     "/health?check=db",
			expected: true,
		},
		{
			name:     "Not a health check",
			path:     "/api/users",
			expected: false,
		},
		{
			name:     "Health-related path (matches prefix)",
			path:     "/healthiness",
			expected: true, // HasPrefix behavior - this actually matches
		},
		{
			name:     "Root path",
			path:     "/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			result := processor.IsHealthCheckRequest(req)

			if result != tt.expected {
				t.Errorf("Expected IsHealthCheckRequest to return %v for path '%s', got %v", tt.expected, tt.path, result)
			}
		})
	}
}

// TestIsEventStreamRequest tests event stream detection
func TestIsEventStreamRequest(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name         string
		acceptHeader string
		expected     bool
	}{
		{
			name:         "Event stream accept header",
			acceptHeader: "text/event-stream",
			expected:     true,
		},
		{
			name:         "Event stream with other types",
			acceptHeader: "text/html, text/event-stream, application/json",
			expected:     true,
		},
		{
			name:         "JSON accept header",
			acceptHeader: "application/json",
			expected:     false,
		},
		{
			name:         "HTML accept header",
			acceptHeader: "text/html,application/xhtml+xml",
			expected:     false,
		},
		{
			name:         "Empty accept header",
			acceptHeader: "",
			expected:     false,
		},
		{
			name:         "Similar but not event stream",
			acceptHeader: "text/event-source",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}

			result := processor.IsEventStreamRequest(req)

			if result != tt.expected {
				t.Errorf("Expected IsEventStreamRequest to return %v for accept header '%s', got %v", tt.expected, tt.acceptHeader, result)
			}
		})
	}
}

// TestIsAjaxRequest tests AJAX request detection
func TestIsAjaxRequest(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name        string
		setupHeader func(*http.Request)
		expected    bool
	}{
		{
			name: "XMLHttpRequest header",
			setupHeader: func(req *http.Request) {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			},
			expected: true,
		},
		{
			name: "JSON content type",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Content-Type", "application/json")
			},
			expected: true,
		},
		{
			name: "JSON content type with charset",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Content-Type", "application/json; charset=utf-8")
			},
			expected: true,
		},
		{
			name: "JSON accept header",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Accept", "application/json")
			},
			expected: true,
		},
		{
			name: "JSON accept with other types",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Accept", "text/html, application/json, application/xml")
			},
			expected: true,
		},
		{
			name: "Multiple AJAX indicators",
			setupHeader: func(req *http.Request) {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json")
			},
			expected: true,
		},
		{
			name: "Regular HTML request",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Accept", "text/html,application/xhtml+xml")
			},
			expected: false,
		},
		{
			name: "Form submission",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			},
			expected: false,
		},
		{
			name:        "No special headers",
			setupHeader: func(req *http.Request) {},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://example.com/api", nil)
			tt.setupHeader(req)

			result := processor.IsAjaxRequest(req)

			if result != tt.expected {
				t.Errorf("Expected IsAjaxRequest to return %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestWaitForInitialization tests initialization waiting
func TestWaitForInitialization(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	t.Run("Initialization completes successfully", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		initComplete := make(chan struct{})

		go func() {
			time.Sleep(10 * time.Millisecond)
			close(initComplete)
		}()

		err := processor.WaitForInitialization(req, initComplete)
		if err != nil {
			t.Errorf("Expected no error when initialization completes, got: %v", err)
		}
	})

	t.Run("Request context canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		req = req.WithContext(ctx)
		initComplete := make(chan struct{})

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		err := processor.WaitForInitialization(req, initComplete)
		if err == nil {
			t.Error("Expected error when request context is canceled")
		}

		if !strings.Contains(err.Error(), "request canceled") {
			t.Errorf("Expected 'request canceled' error, got: %v", err)
		}

		if len(logger.DebugCalls) == 0 {
			t.Error("Expected debug log when request is canceled")
		}
	})

	t.Run("Initialization timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping timeout test in short mode")
		}

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		initComplete := make(chan struct{}) // Never closes

		// Note: This test takes 30 seconds due to hardcoded timeout in implementation
		start := time.Now()
		err := processor.WaitForInitialization(req, initComplete)
		duration := time.Since(start)

		if err == nil {
			t.Error("Expected timeout error")
		}

		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("Expected timeout error, got: %v", err)
		}

		// The timeout should be around 30 seconds, allow some variance
		if duration < 29*time.Second || duration > 31*time.Second {
			t.Errorf("Expected timeout after ~30 seconds, but got %v", duration)
		}

		if len(logger.ErrorCalls) == 0 {
			t.Error("Expected error log when timeout occurs")
		}
	})
}

// TestDetermineScheme tests scheme determination
func TestDetermineScheme(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "X-Forwarded-Proto HTTPS",
			setup: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Proto", "https")
			},
			expected: "https",
		},
		{
			name: "X-Forwarded-Proto HTTP",
			setup: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Proto", "http")
			},
			expected: "http",
		},
		{
			name: "TLS connection without header",
			setup: func(req *http.Request) {
				req.TLS = &tls.ConnectionState{}
			},
			expected: "https",
		},
		{
			name: "No TLS, no header",
			setup: func(req *http.Request) {
				// No special setup
			},
			expected: "http",
		},
		{
			name: "X-Forwarded-Proto takes precedence over TLS",
			setup: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Proto", "http")
				req.TLS = &tls.ConnectionState{}
			},
			expected: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			tt.setup(req)

			result := processor.determineScheme(req)

			if result != tt.expected {
				t.Errorf("Expected scheme '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestDetermineHost tests host determination
func TestDetermineHost(t *testing.T) {
	logger := &MockLogger{}
	processor := NewRequestProcessor(logger)

	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "X-Forwarded-Host header present",
			setup: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Host", "public.example.com")
			},
			expected: "public.example.com",
		},
		{
			name: "No X-Forwarded-Host, use req.Host",
			setup: func(req *http.Request) {
				// No special setup, will use req.Host
			},
			expected: "example.com",
		},
		{
			name: "Empty X-Forwarded-Host, fallback to req.Host",
			setup: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Host", "")
			},
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			tt.setup(req)

			result := processor.determineHost(req)

			if result != tt.expected {
				t.Errorf("Expected host '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestBuildFullURL tests URL building
func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		host     string
		path     string
		expected string
	}{
		{
			name:     "Basic URL construction",
			scheme:   "https",
			host:     "example.com",
			path:     "/callback",
			expected: "https://example.com/callback",
		},
		{
			name:     "Path without leading slash",
			scheme:   "http",
			host:     "test.com",
			path:     "auth",
			expected: "http://test.com/auth",
		},
		{
			name:     "Absolute HTTP URL in path",
			scheme:   "https",
			host:     "example.com",
			path:     "http://other.com/callback",
			expected: "http://other.com/callback",
		},
		{
			name:     "Absolute HTTPS URL in path",
			scheme:   "http",
			host:     "example.com",
			path:     "https://secure.com/auth",
			expected: "https://secure.com/auth",
		},
		{
			name:     "Root path",
			scheme:   "https",
			host:     "example.com:8080",
			path:     "/",
			expected: "https://example.com:8080/",
		},
		{
			name:     "Empty path",
			scheme:   "https",
			host:     "example.com",
			path:     "",
			expected: "https://example.com/",
		},
		{
			name:     "Path with query parameters",
			scheme:   "https",
			host:     "example.com",
			path:     "/callback?state=abc123",
			expected: "https://example.com/callback?state=abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildFullURL(tt.scheme, tt.host, tt.path)

			if result != tt.expected {
				t.Errorf("Expected URL '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestRequestContext tests the RequestContext struct
func TestRequestContext(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rw := httptest.NewRecorder()

	ctx := &RequestContext{
		Writer:      rw,
		Request:     req,
		RedirectURL: "https://example.com/callback",
		Scheme:      "https",
		Host:        "example.com",
	}

	if ctx.Writer != rw {
		t.Error("Expected Writer to be set correctly")
	}

	if ctx.Request != req {
		t.Error("Expected Request to be set correctly")
	}

	if ctx.RedirectURL != "https://example.com/callback" {
		t.Error("Expected RedirectURL to be set correctly")
	}

	if ctx.Scheme != "https" {
		t.Error("Expected Scheme to be set correctly")
	}

	if ctx.Host != "example.com" {
		t.Error("Expected Host to be set correctly")
	}
}
