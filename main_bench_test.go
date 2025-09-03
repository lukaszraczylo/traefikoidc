package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkOIDCMiddleware benchmarks the OIDC middleware's ability to handle concurrent requests.
func BenchmarkOIDCMiddleware(b *testing.B) {
	// Setup test environment

	// Create a testing.T wrapper for benchmarks
	t := &testing.T{}
	ts := NewTestSuite(t)
	ts.Setup()
	ts.token = "valid.jwt.token"

	// Define the handler with OIDC middleware
	ts.tOidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create test server
	server := httptest.NewServer(ts.tOidc.next)
	defer server.Close()

	// Prepare HTTP client
	client := &http.Client{}

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		// Create new request
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			b.Fatal(err)
		}

		// Set necessary headers or cookies
		req.Header.Set("Authorization", "Bearer "+ts.token)

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}

		// Close response body
		resp.Body.Close()

		// Check response status code
		if resp.StatusCode != http.StatusOK {
			b.Errorf("Unexpected status code: got %v, want %v", resp.StatusCode, http.StatusOK)
		}
	}
}
