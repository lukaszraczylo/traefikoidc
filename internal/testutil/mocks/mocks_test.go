package mocks

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestJWKCache(t *testing.T) {
	t.Run("GetJWKS returns configured response", func(t *testing.T) {
		m := new(JWKCache)
		expectedJWKS := &JWKSet{
			Keys: []JWK{{Kty: "RSA", Kid: "test-key"}},
		}

		m.On("GetJWKS", mock.Anything, "https://example.com/jwks", mock.Anything).
			Return(expectedJWKS, nil)

		result, err := m.GetJWKS(context.Background(), "https://example.com/jwks", nil)

		assert.NoError(t, err)
		assert.Equal(t, expectedJWKS, result)
		m.AssertExpectations(t)
	})

	t.Run("GetJWKS returns error", func(t *testing.T) {
		m := new(JWKCache)
		expectedErr := errors.New("network error")

		m.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, expectedErr)

		result, err := m.GetJWKS(context.Background(), "https://example.com/jwks", nil)

		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
		m.AssertExpectations(t)
	})

	t.Run("Close is callable", func(t *testing.T) {
		m := new(JWKCache)
		m.On("Close").Return()

		m.Close()
		m.AssertExpectations(t)
	})
}

func TestTokenExchanger(t *testing.T) {
	t.Run("ExchangeCodeForToken success", func(t *testing.T) {
		m := new(TokenExchanger)
		expectedResp := &TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			IDToken:      "id-token",
			ExpiresIn:    3600,
		}

		m.On("ExchangeCodeForToken", mock.Anything, "authorization_code", "test-code", "https://example.com/callback", "verifier").
			Return(expectedResp, nil)

		result, err := m.ExchangeCodeForToken(context.Background(), "authorization_code", "test-code", "https://example.com/callback", "verifier")

		assert.NoError(t, err)
		assert.Equal(t, expectedResp, result)
		m.AssertExpectations(t)
	})

	t.Run("RefreshToken success", func(t *testing.T) {
		m := new(TokenExchanger)
		expectedResp := &TokenResponse{
			AccessToken: "new-access-token",
			ExpiresIn:   3600,
		}

		m.On("GetNewTokenWithRefreshToken", "refresh-token").
			Return(expectedResp, nil)

		result, err := m.GetNewTokenWithRefreshToken("refresh-token")

		assert.NoError(t, err)
		assert.Equal(t, expectedResp, result)
		m.AssertExpectations(t)
	})

	t.Run("RevokeToken success", func(t *testing.T) {
		m := new(TokenExchanger)
		m.On("RevokeTokenWithProvider", "token", "access_token").Return(nil)

		err := m.RevokeTokenWithProvider("token", "access_token")

		assert.NoError(t, err)
		m.AssertExpectations(t)
	})
}

func TestTokenVerifier(t *testing.T) {
	t.Run("VerifyToken success", func(t *testing.T) {
		m := new(TokenVerifier)
		m.On("VerifyToken", "valid-token").Return(nil)

		err := m.VerifyToken("valid-token")

		assert.NoError(t, err)
		m.AssertExpectations(t)
	})

	t.Run("VerifyToken failure", func(t *testing.T) {
		m := new(TokenVerifier)
		expectedErr := errors.New("token expired")
		m.On("VerifyToken", "expired-token").Return(expectedErr)

		err := m.VerifyToken("expired-token")

		assert.Equal(t, expectedErr, err)
		m.AssertExpectations(t)
	})
}

func TestSessionManager(t *testing.T) {
	t.Run("GetSession returns session", func(t *testing.T) {
		m := new(SessionManager)
		expectedSession := &SessionData{
			Email:       "user@example.com",
			AccessToken: "access-token",
		}

		m.On("GetSession", mock.AnythingOfType("*http.Request")).
			Return(expectedSession, nil)

		req, _ := http.NewRequest("GET", "/", nil)
		result, err := m.GetSession(req)

		assert.NoError(t, err)
		assert.Equal(t, expectedSession, result)
		m.AssertExpectations(t)
	})

	t.Run("SaveSession succeeds", func(t *testing.T) {
		m := new(SessionManager)
		session := &SessionData{Email: "user@example.com"}

		m.On("SaveSession", mock.Anything, mock.Anything, session).Return(nil)

		req, _ := http.NewRequest("GET", "/", nil)
		err := m.SaveSession(req, nil, session)

		assert.NoError(t, err)
		m.AssertExpectations(t)
	})

	t.Run("DeleteSession succeeds", func(t *testing.T) {
		m := new(SessionManager)
		m.On("DeleteSession", mock.Anything, mock.Anything).Return(nil)

		req, _ := http.NewRequest("GET", "/", nil)
		err := m.DeleteSession(req, nil)

		assert.NoError(t, err)
		m.AssertExpectations(t)
	})
}

func TestCache(t *testing.T) {
	t.Run("Get returns value", func(t *testing.T) {
		m := new(Cache)
		m.On("Get", "key").Return("value", true)

		result, found := m.Get("key")

		assert.True(t, found)
		assert.Equal(t, "value", result)
		m.AssertExpectations(t)
	})

	t.Run("Get returns not found", func(t *testing.T) {
		m := new(Cache)
		m.On("Get", "missing").Return(nil, false)

		result, found := m.Get("missing")

		assert.False(t, found)
		assert.Nil(t, result)
		m.AssertExpectations(t)
	})

	t.Run("SetWithTTL is callable", func(t *testing.T) {
		m := new(Cache)
		m.On("SetWithTTL", "key", "value", 5*time.Minute).Return()

		m.SetWithTTL("key", "value", 5*time.Minute)
		m.AssertExpectations(t)
	})

	t.Run("Delete is callable", func(t *testing.T) {
		m := new(Cache)
		m.On("Delete", "key").Return()

		m.Delete("key")
		m.AssertExpectations(t)
	})
}

func TestHTTPClient(t *testing.T) {
	t.Run("Do returns response", func(t *testing.T) {
		m := new(HTTPClient)
		expectedResp := &http.Response{StatusCode: 200}

		m.On("Do", mock.AnythingOfType("*http.Request")).Return(expectedResp, nil)

		req, _ := http.NewRequest("GET", "https://example.com", nil)
		result, err := m.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 200, result.StatusCode)
		m.AssertExpectations(t)
	})

	t.Run("Do returns error", func(t *testing.T) {
		m := new(HTTPClient)
		expectedErr := errors.New("connection refused")

		m.On("Do", mock.Anything).Return(nil, expectedErr)

		req, _ := http.NewRequest("GET", "https://example.com", nil)
		result, err := m.Do(req)

		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
		m.AssertExpectations(t)
	})
}

func TestLogger(t *testing.T) {
	t.Run("Debug is callable", func(t *testing.T) {
		m := new(Logger)
		m.On("Debug", "test message").Return()

		m.Debug("test message")
		m.AssertExpectations(t)
	})

	t.Run("Error is callable", func(t *testing.T) {
		m := new(Logger)
		m.On("Error", "error message").Return()

		m.Error("error message")
		m.AssertExpectations(t)
	})
}
