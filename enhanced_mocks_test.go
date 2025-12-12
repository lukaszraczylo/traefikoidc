package traefikoidc

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stretchr/testify/assert"
)

// EnhancedMockJWKCache is an improved state-based mock with call tracking
type EnhancedMockJWKCache struct {
	Err            error
	JWKS           *JWKSet
	GetJWKSCalls   []JWKSCall
	mu             sync.RWMutex
	getJWKSCallsMu sync.Mutex
	CleanupCalls   int32
	CloseCalls     int32
}

// JWKSCall records parameters from a GetJWKS call
type JWKSCall struct {
	Timestamp time.Time
	URL       string
}

func (m *EnhancedMockJWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	m.getJWKSCallsMu.Lock()
	m.GetJWKSCalls = append(m.GetJWKSCalls, JWKSCall{
		URL:       jwksURL,
		Timestamp: time.Now(),
	})
	m.getJWKSCallsMu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.JWKS, m.Err
}

func (m *EnhancedMockJWKCache) Cleanup() {
	atomic.AddInt32(&m.CleanupCalls, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JWKS = nil
	m.Err = nil
}

func (m *EnhancedMockJWKCache) Close() {
	atomic.AddInt32(&m.CloseCalls, 1)
}

// Assertion helpers

// AssertGetJWKSCalled verifies GetJWKS was called
func (m *EnhancedMockJWKCache) AssertGetJWKSCalled(t assert.TestingT) bool {
	m.getJWKSCallsMu.Lock()
	defer m.getJWKSCallsMu.Unlock()
	return assert.NotEmpty(t, m.GetJWKSCalls, "GetJWKS should have been called")
}

// AssertGetJWKSCalledWith verifies GetJWKS was called with specific URL
func (m *EnhancedMockJWKCache) AssertGetJWKSCalledWith(t assert.TestingT, expectedURL string) bool {
	m.getJWKSCallsMu.Lock()
	defer m.getJWKSCallsMu.Unlock()
	for _, call := range m.GetJWKSCalls {
		if call.URL == expectedURL {
			return true
		}
	}
	return assert.Fail(t, "GetJWKS was not called with URL: "+expectedURL)
}

// AssertGetJWKSCallCount verifies the number of GetJWKS calls
func (m *EnhancedMockJWKCache) AssertGetJWKSCallCount(t assert.TestingT, expected int) bool {
	m.getJWKSCallsMu.Lock()
	defer m.getJWKSCallsMu.Unlock()
	return assert.Equal(t, expected, len(m.GetJWKSCalls), "GetJWKS call count mismatch")
}

// GetJWKSCallCount returns the number of GetJWKS calls
func (m *EnhancedMockJWKCache) GetJWKSCallCount() int {
	m.getJWKSCallsMu.Lock()
	defer m.getJWKSCallsMu.Unlock()
	return len(m.GetJWKSCalls)
}

// Reset clears all state and call tracking
func (m *EnhancedMockJWKCache) Reset() {
	m.mu.Lock()
	m.JWKS = nil
	m.Err = nil
	m.mu.Unlock()

	m.getJWKSCallsMu.Lock()
	m.GetJWKSCalls = nil
	m.getJWKSCallsMu.Unlock()

	atomic.StoreInt32(&m.CleanupCalls, 0)
	atomic.StoreInt32(&m.CloseCalls, 0)
}

// EnhancedMockTokenVerifier is an improved state-based mock with call tracking
type EnhancedMockTokenVerifier struct {
	Err           error
	VerifyFunc    func(token string) error
	VerifyCalls   []TokenVerifyCall
	mu            sync.RWMutex
	verifyCallsMu sync.Mutex
}

// TokenVerifyCall records parameters from a VerifyToken call
type TokenVerifyCall struct {
	Timestamp time.Time
	Result    error
	Token     string
}

func (m *EnhancedMockTokenVerifier) VerifyToken(token string) error {
	var result error

	m.mu.RLock()
	if m.VerifyFunc != nil {
		result = m.VerifyFunc(token)
	} else {
		result = m.Err
	}
	m.mu.RUnlock()

	m.verifyCallsMu.Lock()
	m.VerifyCalls = append(m.VerifyCalls, TokenVerifyCall{
		Token:     token,
		Timestamp: time.Now(),
		Result:    result,
	})
	m.verifyCallsMu.Unlock()

	return result
}

// Assertion helpers

// AssertVerifyTokenCalled verifies VerifyToken was called
func (m *EnhancedMockTokenVerifier) AssertVerifyTokenCalled(t assert.TestingT) bool {
	m.verifyCallsMu.Lock()
	defer m.verifyCallsMu.Unlock()
	return assert.NotEmpty(t, m.VerifyCalls, "VerifyToken should have been called")
}

// AssertVerifyTokenCalledWith verifies VerifyToken was called with specific token
func (m *EnhancedMockTokenVerifier) AssertVerifyTokenCalledWith(t assert.TestingT, expectedToken string) bool {
	m.verifyCallsMu.Lock()
	defer m.verifyCallsMu.Unlock()
	for _, call := range m.VerifyCalls {
		if call.Token == expectedToken {
			return true
		}
	}
	return assert.Fail(t, "VerifyToken was not called with expected token")
}

// AssertVerifyTokenCallCount verifies the number of VerifyToken calls
func (m *EnhancedMockTokenVerifier) AssertVerifyTokenCallCount(t assert.TestingT, expected int) bool {
	m.verifyCallsMu.Lock()
	defer m.verifyCallsMu.Unlock()
	return assert.Equal(t, expected, len(m.VerifyCalls), "VerifyToken call count mismatch")
}

// GetVerifyTokenCallCount returns the number of VerifyToken calls
func (m *EnhancedMockTokenVerifier) GetVerifyTokenCallCount() int {
	m.verifyCallsMu.Lock()
	defer m.verifyCallsMu.Unlock()
	return len(m.VerifyCalls)
}

// LastCall returns the most recent VerifyToken call
func (m *EnhancedMockTokenVerifier) LastCall() *TokenVerifyCall {
	m.verifyCallsMu.Lock()
	defer m.verifyCallsMu.Unlock()
	if len(m.VerifyCalls) == 0 {
		return nil
	}
	return &m.VerifyCalls[len(m.VerifyCalls)-1]
}

// Reset clears all state and call tracking
func (m *EnhancedMockTokenVerifier) Reset() {
	m.mu.Lock()
	m.Err = nil
	m.VerifyFunc = nil
	m.mu.Unlock()

	m.verifyCallsMu.Lock()
	m.VerifyCalls = nil
	m.verifyCallsMu.Unlock()
}

// EnhancedMockTokenExchanger is an improved state-based mock with call tracking
type EnhancedMockTokenExchanger struct {
	RefreshErr       error
	RevokeErr        error
	ExchangeErr      error
	ExchangeCodeFunc func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error)
	RefreshResponse  *TokenResponse
	ExchangeResponse *TokenResponse
	RefreshTokenFunc func(refreshToken string) (*TokenResponse, error)
	RevokeTokenFunc  func(token, tokenType string) error
	ExchangeCalls    []ExchangeCall
	RefreshCalls     []RefreshCall
	RevokeCalls      []RevokeCall
	mu               sync.RWMutex
	exchangeCallsMu  sync.Mutex
	refreshCallsMu   sync.Mutex
	revokeCallsMu    sync.Mutex
}

// ExchangeCall records parameters from an ExchangeCodeForToken call
type ExchangeCall struct {
	Timestamp    time.Time
	GrantType    string
	CodeOrToken  string
	RedirectURL  string
	CodeVerifier string
}

// RefreshCall records parameters from a GetNewTokenWithRefreshToken call
type RefreshCall struct {
	Timestamp    time.Time
	RefreshToken string
}

// RevokeCall records parameters from a RevokeTokenWithProvider call
type RevokeCall struct {
	Timestamp time.Time
	Token     string
	TokenType string
}

func (m *EnhancedMockTokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	m.exchangeCallsMu.Lock()
	m.ExchangeCalls = append(m.ExchangeCalls, ExchangeCall{
		GrantType:    grantType,
		CodeOrToken:  codeOrToken,
		RedirectURL:  redirectURL,
		CodeVerifier: codeVerifier,
		Timestamp:    time.Now(),
	})
	m.exchangeCallsMu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ExchangeCodeFunc != nil {
		return m.ExchangeCodeFunc(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
	}
	return m.ExchangeResponse, m.ExchangeErr
}

func (m *EnhancedMockTokenExchanger) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	m.refreshCallsMu.Lock()
	m.RefreshCalls = append(m.RefreshCalls, RefreshCall{
		RefreshToken: refreshToken,
		Timestamp:    time.Now(),
	})
	m.refreshCallsMu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(refreshToken)
	}
	return m.RefreshResponse, m.RefreshErr
}

func (m *EnhancedMockTokenExchanger) RevokeTokenWithProvider(token, tokenType string) error {
	m.revokeCallsMu.Lock()
	m.RevokeCalls = append(m.RevokeCalls, RevokeCall{
		Token:     token,
		TokenType: tokenType,
		Timestamp: time.Now(),
	})
	m.revokeCallsMu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.RevokeTokenFunc != nil {
		return m.RevokeTokenFunc(token, tokenType)
	}
	return m.RevokeErr
}

// Assertion helpers

// AssertExchangeCalled verifies ExchangeCodeForToken was called
func (m *EnhancedMockTokenExchanger) AssertExchangeCalled(t assert.TestingT) bool {
	m.exchangeCallsMu.Lock()
	defer m.exchangeCallsMu.Unlock()
	return assert.NotEmpty(t, m.ExchangeCalls, "ExchangeCodeForToken should have been called")
}

// AssertExchangeCalledWith verifies ExchangeCodeForToken was called with specific grant type
func (m *EnhancedMockTokenExchanger) AssertExchangeCalledWith(t assert.TestingT, grantType string) bool {
	m.exchangeCallsMu.Lock()
	defer m.exchangeCallsMu.Unlock()
	for _, call := range m.ExchangeCalls {
		if call.GrantType == grantType {
			return true
		}
	}
	return assert.Fail(t, "ExchangeCodeForToken was not called with grant type: "+grantType)
}

// AssertRefreshCalled verifies GetNewTokenWithRefreshToken was called
func (m *EnhancedMockTokenExchanger) AssertRefreshCalled(t assert.TestingT) bool {
	m.refreshCallsMu.Lock()
	defer m.refreshCallsMu.Unlock()
	return assert.NotEmpty(t, m.RefreshCalls, "GetNewTokenWithRefreshToken should have been called")
}

// AssertRevokeCalled verifies RevokeTokenWithProvider was called
func (m *EnhancedMockTokenExchanger) AssertRevokeCalled(t assert.TestingT) bool {
	m.revokeCallsMu.Lock()
	defer m.revokeCallsMu.Unlock()
	return assert.NotEmpty(t, m.RevokeCalls, "RevokeTokenWithProvider should have been called")
}

// GetExchangeCallCount returns the number of ExchangeCodeForToken calls
func (m *EnhancedMockTokenExchanger) GetExchangeCallCount() int {
	m.exchangeCallsMu.Lock()
	defer m.exchangeCallsMu.Unlock()
	return len(m.ExchangeCalls)
}

// GetRefreshCallCount returns the number of GetNewTokenWithRefreshToken calls
func (m *EnhancedMockTokenExchanger) GetRefreshCallCount() int {
	m.refreshCallsMu.Lock()
	defer m.refreshCallsMu.Unlock()
	return len(m.RefreshCalls)
}

// GetRevokeCallCount returns the number of RevokeTokenWithProvider calls
func (m *EnhancedMockTokenExchanger) GetRevokeCallCount() int {
	m.revokeCallsMu.Lock()
	defer m.revokeCallsMu.Unlock()
	return len(m.RevokeCalls)
}

// LastExchangeCall returns the most recent ExchangeCodeForToken call
func (m *EnhancedMockTokenExchanger) LastExchangeCall() *ExchangeCall {
	m.exchangeCallsMu.Lock()
	defer m.exchangeCallsMu.Unlock()
	if len(m.ExchangeCalls) == 0 {
		return nil
	}
	return &m.ExchangeCalls[len(m.ExchangeCalls)-1]
}

// Reset clears all state and call tracking
func (m *EnhancedMockTokenExchanger) Reset() {
	m.mu.Lock()
	m.ExchangeResponse = nil
	m.ExchangeErr = nil
	m.RefreshResponse = nil
	m.RefreshErr = nil
	m.RevokeErr = nil
	m.ExchangeCodeFunc = nil
	m.RefreshTokenFunc = nil
	m.RevokeTokenFunc = nil
	m.mu.Unlock()

	m.exchangeCallsMu.Lock()
	m.ExchangeCalls = nil
	m.exchangeCallsMu.Unlock()

	m.refreshCallsMu.Lock()
	m.RefreshCalls = nil
	m.refreshCallsMu.Unlock()

	m.revokeCallsMu.Lock()
	m.RevokeCalls = nil
	m.revokeCallsMu.Unlock()
}

// EnhancedMockCacheInterface is an improved state-based mock for CacheInterface
type EnhancedMockCacheInterface struct {
	data        map[string]cacheEntry
	GetCalls    []CacheGetCall
	SetCalls    []CacheSetCall
	DeleteCalls []string
	maxSize     int
	mu          sync.RWMutex
	getCalls    sync.Mutex
	setCalls    sync.Mutex
	deleteCalls sync.Mutex
}

type cacheEntry struct {
	value any
	ttl   time.Duration
}

// CacheGetCall records parameters from a Get call
type CacheGetCall struct {
	Timestamp time.Time
	Key       string
	Found     bool
}

// CacheSetCall records parameters from a Set call
type CacheSetCall struct {
	Timestamp time.Time
	Value     any
	Key       string
	TTL       time.Duration
}

// NewEnhancedMockCache creates a new enhanced cache mock
func NewEnhancedMockCache() *EnhancedMockCacheInterface {
	return &EnhancedMockCacheInterface{
		data:    make(map[string]cacheEntry),
		maxSize: 1000,
	}
}

func (m *EnhancedMockCacheInterface) Set(key string, value any, ttl time.Duration) {
	m.setCalls.Lock()
	m.SetCalls = append(m.SetCalls, CacheSetCall{
		Key:       key,
		Value:     value,
		TTL:       ttl,
		Timestamp: time.Now(),
	})
	m.setCalls.Unlock()

	m.mu.Lock()
	m.data[key] = cacheEntry{value: value, ttl: ttl}
	m.mu.Unlock()
}

func (m *EnhancedMockCacheInterface) Get(key string) (any, bool) {
	m.mu.RLock()
	entry, found := m.data[key]
	m.mu.RUnlock()

	m.getCalls.Lock()
	m.GetCalls = append(m.GetCalls, CacheGetCall{
		Key:       key,
		Found:     found,
		Timestamp: time.Now(),
	})
	m.getCalls.Unlock()

	if found {
		return entry.value, true
	}
	return nil, false
}

func (m *EnhancedMockCacheInterface) Delete(key string) {
	m.deleteCalls.Lock()
	m.DeleteCalls = append(m.DeleteCalls, key)
	m.deleteCalls.Unlock()

	m.mu.Lock()
	delete(m.data, key)
	m.mu.Unlock()
}

func (m *EnhancedMockCacheInterface) SetMaxSize(size int) {
	m.mu.Lock()
	m.maxSize = size
	m.mu.Unlock()
}

func (m *EnhancedMockCacheInterface) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *EnhancedMockCacheInterface) Clear() {
	m.mu.Lock()
	m.data = make(map[string]cacheEntry)
	m.mu.Unlock()
}

func (m *EnhancedMockCacheInterface) Cleanup() {
	// No-op for mock
}

func (m *EnhancedMockCacheInterface) Close() {
	// No-op for mock
}

func (m *EnhancedMockCacheInterface) GetStats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"size":     len(m.data),
		"max_size": m.maxSize,
	}
}

// Assertion helpers

// AssertGetCalled verifies Get was called with specific key
func (m *EnhancedMockCacheInterface) AssertGetCalled(t assert.TestingT, key string) bool {
	m.getCalls.Lock()
	defer m.getCalls.Unlock()
	for _, call := range m.GetCalls {
		if call.Key == key {
			return true
		}
	}
	return assert.Fail(t, "Get was not called with key: "+key)
}

// AssertSetCalled verifies Set was called with specific key
func (m *EnhancedMockCacheInterface) AssertSetCalled(t assert.TestingT, key string) bool {
	m.setCalls.Lock()
	defer m.setCalls.Unlock()
	for _, call := range m.SetCalls {
		if call.Key == key {
			return true
		}
	}
	return assert.Fail(t, "Set was not called with key: "+key)
}

// AssertDeleteCalled verifies Delete was called with specific key
func (m *EnhancedMockCacheInterface) AssertDeleteCalled(t assert.TestingT, key string) bool {
	m.deleteCalls.Lock()
	defer m.deleteCalls.Unlock()
	for _, k := range m.DeleteCalls {
		if k == key {
			return true
		}
	}
	return assert.Fail(t, "Delete was not called with key: "+key)
}

// GetCallCount returns the number of Get calls
func (m *EnhancedMockCacheInterface) GetCallCount() int {
	m.getCalls.Lock()
	defer m.getCalls.Unlock()
	return len(m.GetCalls)
}

// SetCallCount returns the number of Set calls
func (m *EnhancedMockCacheInterface) SetCallCount() int {
	m.setCalls.Lock()
	defer m.setCalls.Unlock()
	return len(m.SetCalls)
}

// Reset clears all state and call tracking
func (m *EnhancedMockCacheInterface) Reset() {
	m.mu.Lock()
	m.data = make(map[string]cacheEntry)
	m.mu.Unlock()

	m.getCalls.Lock()
	m.GetCalls = nil
	m.getCalls.Unlock()

	m.setCalls.Lock()
	m.SetCalls = nil
	m.setCalls.Unlock()

	m.deleteCalls.Lock()
	m.DeleteCalls = nil
	m.deleteCalls.Unlock()
}
