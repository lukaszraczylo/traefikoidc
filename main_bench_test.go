// main_bench_test.go
package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/mock"
)

func BenchmarkServeHTTP_AuthenticatedUser(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["authenticated"] = true

	claims := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	claimsJSON, _ := json.Marshal(claims)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	mockToken := fmt.Sprintf("header.%s.signature", encodedClaims)
	session.Values["id_token"] = mockToken

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	suite.mockTokenVerifier.On("VerifyToken", mockToken).Return(nil)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	suite.oidc.next = nextHandler

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw := httptest.NewRecorder()
		suite.oidc.ServeHTTP(rw, req)
	}
}

func BenchmarkVerifyToken(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()

	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkxMjJ9.ZmFrZV9zaWduYXR1cmU"
	suite.mockTokenVerifier.On("VerifyToken", token).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.oidc.verifyToken(token)
	}
}

func BenchmarkBuildAuthURL(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.oidc.buildAuthURL("http://example.com/callback", "test_state", "test_nonce")
	}
}

func BenchmarkJWKToPEM(b *testing.B) {
	jwk := &JWK{
		N: base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jwkToPEM(jwk)
	}
}

func BenchmarkTokenBlacklist_Add(b *testing.B) {
	tb := NewTokenBlacklist()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Add(token, expiration)
	}
}

func BenchmarkTokenBlacklist_IsBlacklisted(b *testing.B) {
	tb := NewTokenBlacklist()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)
	tb.Add(token, expiration)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.IsBlacklisted(token)
	}
}

func BenchmarkTokenCache_Set(b *testing.B) {
	tc := NewTokenCache()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc.Set(token, expiration)
	}
}

func BenchmarkTokenCache_Get(b *testing.B) {
	tc := NewTokenCache()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)
	tc.Set(token, expiration)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc.Get(token)
	}
}

func BenchmarkExtractClaims(b *testing.B) {
	tokenString := "header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractClaims(tokenString)
	}
}

func BenchmarkDetermineScheme(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.oidc.determineScheme(req)
	}
}

func BenchmarkDetermineHost(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Forwarded-Host", "forwarded.example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.oidc.determineHost(req)
	}
}

func BenchmarkIsUserAuthenticated(b *testing.B) {
	suite := new(TraefikOidcTestSuite)
	suite.SetupTest()
	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["authenticated"] = true
	session.Values["id_token"] = "valid.eyJleHAiOjk5OTk5OTk5OTl9.signature"

	suite.mockTokenVerifier.On("VerifyToken", "valid.eyJleHAiOjk5OTk5OTk5OTl9.signature").Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.oidc.isUserAuthenticated(session)
	}
}
