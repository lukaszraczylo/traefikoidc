package traefikoidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// EnhancedMocksSuite demonstrates improved state-based mocks with call tracking
type EnhancedMocksSuite struct {
	suite.Suite
}

func (s *EnhancedMocksSuite) TestEnhancedJWKCacheCallTracking() {
	mock := &EnhancedMockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{{Kid: "test-key"}}},
	}

	// Make some calls
	result, err := mock.GetJWKS(context.Background(), "https://example.com/jwks", nil)
	s.NoError(err)
	s.NotNil(result)

	// Another call with different URL
	_, _ = mock.GetJWKS(context.Background(), "https://other.com/jwks", nil)

	// Verify calls were tracked
	s.Equal(2, mock.GetJWKSCallCount())
	mock.AssertGetJWKSCalled(s.T())
	mock.AssertGetJWKSCalledWith(s.T(), "https://example.com/jwks")
	mock.AssertGetJWKSCallCount(s.T(), 2)
}

func (s *EnhancedMocksSuite) TestEnhancedJWKCacheWithError() {
	expectedErr := errors.New("network error")
	mock := &EnhancedMockJWKCache{
		Err: expectedErr,
	}

	result, err := mock.GetJWKS(context.Background(), "https://example.com/jwks", nil)

	s.Nil(result)
	s.Equal(expectedErr, err)
	mock.AssertGetJWKSCalled(s.T())
}

func (s *EnhancedMocksSuite) TestEnhancedJWKCacheReset() {
	mock := &EnhancedMockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{{Kid: "test-key"}}},
	}

	_, _ = mock.GetJWKS(context.Background(), "https://example.com/jwks", nil)
	s.Equal(1, mock.GetJWKSCallCount())

	mock.Reset()

	s.Equal(0, mock.GetJWKSCallCount())
	s.Nil(mock.JWKS)
}

func (s *EnhancedMocksSuite) TestEnhancedTokenVerifierCallTracking() {
	mock := &EnhancedMockTokenVerifier{
		Err: nil, // Valid tokens
	}

	// Verify a token
	err := mock.VerifyToken("test-token-1")
	s.NoError(err)

	// Verify another token
	err = mock.VerifyToken("test-token-2")
	s.NoError(err)

	// Check tracking
	s.Equal(2, mock.GetVerifyTokenCallCount())
	mock.AssertVerifyTokenCalled(s.T())
	mock.AssertVerifyTokenCalledWith(s.T(), "test-token-1")

	// Check last call
	lastCall := mock.LastCall()
	s.NotNil(lastCall)
	s.Equal("test-token-2", lastCall.Token)
}

func (s *EnhancedMocksSuite) TestEnhancedTokenVerifierWithDynamicFunc() {
	callCount := 0
	mock := &EnhancedMockTokenVerifier{
		VerifyFunc: func(token string) error {
			callCount++
			if token == "invalid" {
				return errors.New("invalid token")
			}
			return nil
		},
	}

	// Valid token
	err := mock.VerifyToken("valid-token")
	s.NoError(err)

	// Invalid token
	err = mock.VerifyToken("invalid")
	s.Error(err)

	s.Equal(2, callCount)
	s.Equal(2, mock.GetVerifyTokenCallCount())
}

func (s *EnhancedMocksSuite) TestEnhancedTokenExchangerCallTracking() {
	mock := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
		},
		RefreshResponse: &TokenResponse{
			AccessToken: "new-access-token",
			ExpiresIn:   3600,
		},
	}

	// Exchange code
	resp, err := mock.ExchangeCodeForToken(context.Background(), "authorization_code", "auth-code", "https://redirect.com", "verifier")
	s.NoError(err)
	s.Equal("access-token", resp.AccessToken)

	// Refresh token
	resp, err = mock.GetNewTokenWithRefreshToken("refresh-token")
	s.NoError(err)
	s.Equal("new-access-token", resp.AccessToken)

	// Revoke token
	err = mock.RevokeTokenWithProvider("access-token", "access_token")
	s.NoError(err)

	// Check tracking
	mock.AssertExchangeCalled(s.T())
	mock.AssertExchangeCalledWith(s.T(), "authorization_code")
	mock.AssertRefreshCalled(s.T())
	mock.AssertRevokeCalled(s.T())

	s.Equal(1, mock.GetExchangeCallCount())
	s.Equal(1, mock.GetRefreshCallCount())
	s.Equal(1, mock.GetRevokeCallCount())

	// Check last exchange call details
	lastExchange := mock.LastExchangeCall()
	s.NotNil(lastExchange)
	s.Equal("authorization_code", lastExchange.GrantType)
	s.Equal("auth-code", lastExchange.CodeOrToken)
	s.Equal("https://redirect.com", lastExchange.RedirectURL)
}

func (s *EnhancedMocksSuite) TestEnhancedTokenExchangerWithErrors() {
	mock := &EnhancedMockTokenExchanger{
		ExchangeErr: errors.New("invalid_grant"),
		RefreshErr:  errors.New("refresh_expired"),
		RevokeErr:   errors.New("revoke_failed"),
	}

	_, err := mock.ExchangeCodeForToken(context.Background(), "authorization_code", "code", "", "")
	s.Error(err)
	s.Contains(err.Error(), "invalid_grant")

	_, err = mock.GetNewTokenWithRefreshToken("token")
	s.Error(err)
	s.Contains(err.Error(), "refresh_expired")

	err = mock.RevokeTokenWithProvider("token", "access_token")
	s.Error(err)
	s.Contains(err.Error(), "revoke_failed")
}

func (s *EnhancedMocksSuite) TestEnhancedCacheCallTracking() {
	mock := NewEnhancedMockCache()

	// Set some values
	mock.Set("key1", "value1", 5*time.Minute)
	mock.Set("key2", "value2", 10*time.Minute)

	// Get values
	val, found := mock.Get("key1")
	s.True(found)
	s.Equal("value1", val)

	_, found = mock.Get("nonexistent")
	s.False(found)

	// Delete
	mock.Delete("key1")

	// Verify tracking
	mock.AssertSetCalled(s.T(), "key1")
	mock.AssertSetCalled(s.T(), "key2")
	mock.AssertGetCalled(s.T(), "key1")
	mock.AssertGetCalled(s.T(), "nonexistent")
	mock.AssertDeleteCalled(s.T(), "key1")

	s.Equal(2, mock.SetCallCount())
	s.Equal(2, mock.GetCallCount())
}

func (s *EnhancedMocksSuite) TestEnhancedCacheActualStorage() {
	mock := NewEnhancedMockCache()

	// The enhanced mock actually stores data
	mock.Set("key", "value", time.Hour)
	s.Equal(1, mock.Size())

	val, found := mock.Get("key")
	s.True(found)
	s.Equal("value", val)

	mock.Delete("key")
	s.Equal(0, mock.Size())

	_, found = mock.Get("key")
	s.False(found)
}

func (s *EnhancedMocksSuite) TestEnhancedCacheClear() {
	mock := NewEnhancedMockCache()

	mock.Set("key1", "value1", time.Hour)
	mock.Set("key2", "value2", time.Hour)
	s.Equal(2, mock.Size())

	mock.Clear()
	s.Equal(0, mock.Size())
}

func (s *EnhancedMocksSuite) TestConcurrentAccess() {
	mock := &EnhancedMockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{{Kid: "test-key"}}},
	}

	// Concurrent calls should be safe
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = mock.GetJWKS(context.Background(), "https://example.com/jwks", nil)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	s.Equal(10, mock.GetJWKSCallCount())
}

func TestEnhancedMocksSuite(t *testing.T) {
	suite.Run(t, new(EnhancedMocksSuite))
}
