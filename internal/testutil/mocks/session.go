package mocks

import (
	"net/http"

	"github.com/stretchr/testify/mock"
)

// SessionData represents session data for testing
type SessionData struct {
	Claims       map[string]interface{}
	Email        string
	AccessToken  string
	RefreshToken string
	IDToken      string
	Nonce        string
	State        string
	CodeVerifier string
	RedirectURL  string
	Expiry       int64
}

// SessionManager is a testify mock for session management
type SessionManager struct {
	mock.Mock
}

// GetSession retrieves a session from the request
func (m *SessionManager) GetSession(r *http.Request) (*SessionData, error) {
	args := m.Called(r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SessionData), args.Error(1)
}

// SaveSession saves a session to the response
func (m *SessionManager) SaveSession(r *http.Request, w http.ResponseWriter, session *SessionData) error {
	args := m.Called(r, w, session)
	return args.Error(0)
}

// DeleteSession removes a session
func (m *SessionManager) DeleteSession(r *http.Request, w http.ResponseWriter) error {
	args := m.Called(r, w)
	return args.Error(0)
}

// SetAccessToken sets the access token in the session
func (m *SessionManager) SetAccessToken(session *SessionData, token string) error {
	args := m.Called(session, token)
	return args.Error(0)
}

// SetRefreshToken sets the refresh token in the session
func (m *SessionManager) SetRefreshToken(session *SessionData, token string) error {
	args := m.Called(session, token)
	return args.Error(0)
}

// SetIDToken sets the ID token in the session
func (m *SessionManager) SetIDToken(session *SessionData, token string) error {
	args := m.Called(session, token)
	return args.Error(0)
}

// GetAccessToken gets the access token from the session
func (m *SessionManager) GetAccessToken(session *SessionData) string {
	args := m.Called(session)
	return args.String(0)
}

// GetRefreshToken gets the refresh token from the session
func (m *SessionManager) GetRefreshToken(session *SessionData) string {
	args := m.Called(session)
	return args.String(0)
}

// GetIDToken gets the ID token from the session
func (m *SessionManager) GetIDToken(session *SessionData) string {
	args := m.Called(session)
	return args.String(0)
}

// IsExpired checks if the session is expired
func (m *SessionManager) IsExpired(session *SessionData) bool {
	args := m.Called(session)
	return args.Bool(0)
}

// CleanupOldCookies removes old/stale cookies
func (m *SessionManager) CleanupOldCookies(r *http.Request, w http.ResponseWriter) {
	m.Called(r, w)
}
