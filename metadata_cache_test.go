package traefikoidc

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestIsCacheValid(t *testing.T) {
	// Setup with a dummy ProviderMetadata.
	pm := &ProviderMetadata{}
	mc := &MetadataCache{
		metadata:  pm,
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	if !mc.isCacheValid() {
		t.Errorf("Expected cache to be valid")
	}
	mc.expiresAt = time.Now().Add(-1 * time.Hour)
	if mc.isCacheValid() {
		t.Errorf("Expected cache to be invalid")
	}
}

func TestCleanup(t *testing.T) {
	pm := &ProviderMetadata{}
	mc := &MetadataCache{
		metadata:  pm,
		expiresAt: time.Now().Add(-1 * time.Hour),
	}
	mc.Cleanup()
	if mc.metadata != nil {
		t.Errorf("Expected metadata to be nil after cleanup")
	}
}

func TestGetMetadata_Cached(t *testing.T) {
	dummyData := &ProviderMetadata{}
	// Construct MetadataCache manually to avoid interference from auto cleanup.
	mc := &MetadataCache{
		metadata:            dummyData,
		expiresAt:           time.Now().Add(1 * time.Hour),
		stopCleanup:         make(chan struct{}),
		autoCleanupInterval: 5 * time.Minute,
	}
	// Use NewLogger to create a logger that writes errors only.
	logger := NewLogger("error")
	result, err := mc.GetMetadata("http://example.com", http.DefaultClient, logger)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result != dummyData {
		t.Errorf("Expected cached metadata to be returned")
	}
}

func TestMetadataCacheAutoCleanup(t *testing.T) {
	mc := &MetadataCache{
		autoCleanupInterval: 50 * time.Millisecond,
		stopCleanup:         make(chan struct{}),
	}
	// Start auto cleanup.
	go mc.startAutoCleanup()
	mc.mutex.Lock()
	mc.metadata = &ProviderMetadata{}
	mc.expiresAt = time.Now().Add(-50 * time.Millisecond)
	mc.mutex.Unlock()

	// Wait enough time for the auto cleanup to run.
	time.Sleep(200 * time.Millisecond)
	mc.Close()
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	if mc.metadata != nil {
		t.Errorf("Expected metadata to be cleared by auto cleanup")
	}
}

type errorRoundTripper struct {
	err error
}

func (e errorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, e.err
}

func TestGetMetadata_FetchError(t *testing.T) {
	// Create an HTTP client that always returns an error.
	errorClient := &http.Client{
		Transport: errorRoundTripper{err: fmt.Errorf("fake fetch error")},
	}

	// Case 1: Cache is empty.
	mc := &MetadataCache{
		stopCleanup: make(chan struct{}),
	}
	logger := NewLogger("error")
	metadata, err := mc.GetMetadata("http://example.com", errorClient, logger)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if metadata != nil {
		t.Errorf("Expected nil metadata, got %v", metadata)
	}

	// Case 2: Cache has old metadata.
	dummy := &ProviderMetadata{}
	mc.metadata = dummy
	mc.expiresAt = time.Now().Add(-1 * time.Minute)
	logger2 := NewLogger("error")
	metadata, err = mc.GetMetadata("http://example.com", errorClient, logger2)
	if err != nil {
		t.Errorf("Expected no error when cached metadata exists, got %v", err)
	}
	if metadata != dummy {
		t.Errorf("Expected cached metadata to be returned")
	}
}