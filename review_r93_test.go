package traefikoidc

import (
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/require"
)

// TestR93CallbackRejectsUnverifiedEmail is a security regression: an email
// used for email/domain authorization must be rejected when the IdP
// explicitly marks it unverified (email_verified == false). Before the R93
// fix the callback admitted the user purely on the matching email string,
// so an attacker registering an unverified address inside an allowed
// domain (or matching an allowed user) could pass the allowlist.
func (s *AuthFlowBehaviourSuite) TestR93CallbackRejectsUnverifiedEmail() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()
	s.tOidc.sessionManager = sessionManager
	// Allow all users so the only blocking condition is email verification.
	s.tOidc.allowedUsers = nil
	s.tOidc.allowedUserDomains = nil

	nonce := "test-nonce-12345"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.signature"

	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      idToken,
			ExpiresIn:    3600,
		},
	}
	s.tOidc.tokenExchanger = mockExchanger
	s.tOidc.tokenVerifier = &EnhancedMockTokenVerifier{Err: nil}

	// Claims carry an email that the IdP explicitly reports as unverified.
	s.tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub":            "1234567890",
			"email":          "attacker@example.com",
			"email_verified": false,
			"nonce":          nonce,
		}, nil
	}

	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	session.SetIncomingPath("/original/protected/path")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Unverified email must be rejected with 403, not admitted.
	s.Equal(http.StatusForbidden, rw2.Code, "callback must reject email_verified=false for email-based authorization")
}

// TestR93CallbackAdmitsVerifiedOrAbsentEmail guards the backward-compatible
// side of the R93 gate: absence of email_verified (the historical norm)
// and email_verified == true both still admit the user.
func (s *AuthFlowBehaviourSuite) TestR93CallbackAdmitsVerifiedOrAbsentEmail() {
	for _, tc := range []struct {
		name          string
		emailVerified interface{}
	}{
		{"absent", nil},
		{"true", true},
	} {
		s.Run(tc.name, func() {
			require := require.New(s.T())
			sessionManager, err := NewSessionManager(
				"test-encryption-key-32-bytes-long!!",
				false,
				"",
				"",
				0,
				s.logger,
			)
			require.NoError(err)
			defer sessionManager.Shutdown()
			s.tOidc.sessionManager = sessionManager
			s.tOidc.allowedUsers = nil
			s.tOidc.allowedUserDomains = nil

			nonce := "test-nonce-12345"
			idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.signature"

			s.tOidc.tokenExchanger = &EnhancedMockTokenExchanger{
				ExchangeResponse: &TokenResponse{
					AccessToken:  "access-token-value",
					RefreshToken: "refresh-token-value",
					IDToken:      idToken,
					ExpiresIn:    3600,
				},
			}
			s.tOidc.tokenVerifier = &EnhancedMockTokenVerifier{Err: nil}
			s.tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
				claims := map[string]interface{}{
					"sub":   "1234567890",
					"email": "user@example.com",
					"nonce": nonce,
				}
				if tc.emailVerified != nil {
					claims["email_verified"] = tc.emailVerified
				}
				return claims, nil
			}

			csrfToken := "valid-csrf-token"
			req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
			rw := httptest.NewRecorder()

			session, err := sessionManager.GetSession(req)
			require.NoError(err)
			session.SetCSRF(csrfToken)
			session.SetNonce(nonce)
			session.SetIncomingPath("/original/protected/path")
			require.NoError(session.Save(req, rw))
			session.returnToPoolSafely()

			req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
			for _, cookie := range rw.Result().Cookies() {
				req2.AddCookie(cookie)
			}
			rw2 := httptest.NewRecorder()

			s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

			require.Equal(http.StatusFound, rw2.Code, "case %s: verified/absent email must be admitted", tc.name)
		})
	}
}
