// Package testing provides unified mock implementations for tests
package testing

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// UnifiedMockLogger provides a standard mock logger for all tests
type UnifiedMockLogger struct {
	LoggedMessages []string
	mu             sync.RWMutex
}

func NewUnifiedMockLogger() *UnifiedMockLogger {
	return &UnifiedMockLogger{
		LoggedMessages: make([]string, 0),
	}
}

func (l *UnifiedMockLogger) Debug(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LoggedMessages = append(l.LoggedMessages, fmt.Sprintf("DEBUG: %s", msg))
}

func (l *UnifiedMockLogger) Debugf(format string, args ...interface{}) {
	l.Debug(fmt.Sprintf(format, args...))
}

func (l *UnifiedMockLogger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LoggedMessages = append(l.LoggedMessages, fmt.Sprintf("INFO: %s", msg))
}

func (l *UnifiedMockLogger) Infof(format string, args ...interface{}) {
	l.Info(fmt.Sprintf(format, args...))
}

func (l *UnifiedMockLogger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LoggedMessages = append(l.LoggedMessages, fmt.Sprintf("ERROR: %s", msg))
}

func (l *UnifiedMockLogger) Errorf(format string, args ...interface{}) {
	l.Error(fmt.Sprintf(format, args...))
}

func (l *UnifiedMockLogger) GetMessages() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]string, len(l.LoggedMessages))
	copy(result, l.LoggedMessages)
	return result
}

func (l *UnifiedMockLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LoggedMessages = l.LoggedMessages[:0]
}

// UnifiedMockSession provides a standard mock session for all tests
type UnifiedMockSession struct {
	authenticated bool
	idToken       string
	accessToken   string
	refreshToken  string
	email         string
	csrf          string
	nonce         string
	codeVerifier  string
	incomingPath  string
	redirectCount int
	mu            sync.RWMutex
}

func NewUnifiedMockSession() *UnifiedMockSession {
	return &UnifiedMockSession{}
}

func (s *UnifiedMockSession) GetAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authenticated
}

func (s *UnifiedMockSession) SetAuthenticated(auth bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authenticated = auth
	return nil
}

func (s *UnifiedMockSession) GetIDToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idToken
}

func (s *UnifiedMockSession) SetIDToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idToken = token
}

func (s *UnifiedMockSession) GetAccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessToken
}

func (s *UnifiedMockSession) SetAccessToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = token
}

func (s *UnifiedMockSession) GetRefreshToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshToken
}

func (s *UnifiedMockSession) SetRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshToken = token
}

func (s *UnifiedMockSession) GetEmail() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.email
}

func (s *UnifiedMockSession) SetEmail(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.email = email
}

func (s *UnifiedMockSession) GetCSRF() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.csrf
}

func (s *UnifiedMockSession) SetCSRF(csrf string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrf = csrf
}

func (s *UnifiedMockSession) GetNonce() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nonce
}

func (s *UnifiedMockSession) SetNonce(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonce = nonce
}

func (s *UnifiedMockSession) GetCodeVerifier() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.codeVerifier
}

func (s *UnifiedMockSession) SetCodeVerifier(verifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeVerifier = verifier
}

func (s *UnifiedMockSession) GetIncomingPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.incomingPath
}

func (s *UnifiedMockSession) SetIncomingPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incomingPath = path
}

func (s *UnifiedMockSession) GetRedirectCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.redirectCount
}

func (s *UnifiedMockSession) IncrementRedirectCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectCount++
}

func (s *UnifiedMockSession) ResetRedirectCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectCount = 0
}

func (s *UnifiedMockSession) Save(req *http.Request, rw http.ResponseWriter) error {
	return nil
}

func (s *UnifiedMockSession) Clear(req *http.Request, rw http.ResponseWriter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authenticated = false
	s.idToken = ""
	s.accessToken = ""
	s.refreshToken = ""
	s.email = ""
	s.csrf = ""
	s.nonce = ""
	s.codeVerifier = ""
	s.incomingPath = ""
	s.redirectCount = 0
	return nil
}

func (s *UnifiedMockSession) MarkDirty() {}

func (s *UnifiedMockSession) IsDirty() bool {
	return false
}

func (s *UnifiedMockSession) ReturnToPoolSafely() {}

// UnifiedMockTokenVerifier provides a standard mock token verifier
type UnifiedMockTokenVerifier struct {
	ShouldFail bool
	Error      error
}

func NewUnifiedMockTokenVerifier() *UnifiedMockTokenVerifier {
	return &UnifiedMockTokenVerifier{}
}

func (v *UnifiedMockTokenVerifier) VerifyToken(token string) error {
	if v.ShouldFail {
		if v.Error != nil {
			return v.Error
		}
		return fmt.Errorf("mock verification failed")
	}
	return nil
}

// UnifiedMockTokenCache provides a standard mock token cache
type UnifiedMockTokenCache struct {
	data map[string]map[string]interface{}
	mu   sync.RWMutex
}

func NewUnifiedMockTokenCache() *UnifiedMockTokenCache {
	return &UnifiedMockTokenCache{
		data: make(map[string]map[string]interface{}),
	}
}

func (c *UnifiedMockTokenCache) Get(key string) (map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists := c.data[key]
	return value, exists
}

func (c *UnifiedMockTokenCache) Set(key string, claims map[string]interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = claims
}

func (c *UnifiedMockTokenCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

func (c *UnifiedMockTokenCache) SetMaxSize(size int) {}

func (c *UnifiedMockTokenCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

func (c *UnifiedMockTokenCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]map[string]interface{})
}

func (c *UnifiedMockTokenCache) Cleanup() {}

func (c *UnifiedMockTokenCache) Close() {}

func (c *UnifiedMockTokenCache) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"size": c.Size(),
	}
}

// UnifiedMockHTTPClient provides a mock HTTP client for tests
type UnifiedMockHTTPClient struct {
	Responses map[string]*http.Response
	Errors    map[string]error
	mu        sync.RWMutex
}

func NewUnifiedMockHTTPClient() *UnifiedMockHTTPClient {
	return &UnifiedMockHTTPClient{
		Responses: make(map[string]*http.Response),
		Errors:    make(map[string]error),
	}
}

func (c *UnifiedMockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	url := req.URL.String()
	if err, exists := c.Errors[url]; exists {
		return nil, err
	}
	if resp, exists := c.Responses[url]; exists {
		return resp, nil
	}

	// Default response
	return &http.Response{
		StatusCode: 200,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

func (c *UnifiedMockHTTPClient) SetResponse(url string, response *http.Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Responses[url] = response
}

func (c *UnifiedMockHTTPClient) SetError(url string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Errors[url] = err
}

// TestSuite provides a unified test setup and teardown
type TestSuite struct {
	Logger        *UnifiedMockLogger
	Session       *UnifiedMockSession
	TokenVerifier *UnifiedMockTokenVerifier
	TokenCache    *UnifiedMockTokenCache
	HTTPClient    *UnifiedMockHTTPClient
}

func NewTestSuite() *TestSuite {
	return &TestSuite{
		Logger:        NewUnifiedMockLogger(),
		Session:       NewUnifiedMockSession(),
		TokenVerifier: NewUnifiedMockTokenVerifier(),
		TokenCache:    NewUnifiedMockTokenCache(),
		HTTPClient:    NewUnifiedMockHTTPClient(),
	}
}

func (ts *TestSuite) Setup() {
	// Common test setup
	ts.Logger.Clear()
	_ = ts.Session.Clear(nil, nil) // Safe to ignore: test helper function
	ts.TokenCache.Clear()
	ts.TokenVerifier.ShouldFail = false
	ts.TokenVerifier.Error = nil
}

func (ts *TestSuite) Teardown() {
	// Common test teardown
	ts.TokenCache.Close()
}
