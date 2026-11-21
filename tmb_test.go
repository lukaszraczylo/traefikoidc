package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Example path used as the configured value in these tests.
const tmbPath = "/auth/session"

const (
	tmbTestRefresh = "tmb-refresh-token-0123456789abcdefghijklmnopqrstuvwxyz"
	tmbTestRotated = "tmb-rotated-token-0123456789abcdefghijklmnopqrstuvwxyz"
)

// tmbIdP is a fake token endpoint recording each form it receives.
type tmbIdP struct {
	mu     sync.Mutex
	forms  []url.Values
	status int
	body   string
}

func (p *tmbIdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	p.forms = append(p.forms, r.PostForm)
	status, body := p.status, p.body
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (p *tmbIdP) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.forms)
}

func (p *tmbIdP) last(t *testing.T) url.Values {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotEmpty(t, p.forms, "token endpoint was not called")
	return p.forms[len(p.forms)-1]
}

type tmbEnv struct {
	oidc      *TraefikOidc
	idp       *tmbIdP
	cookies   []*http.Cookie
	access    string // the session's access token
	newAccess string // what a refresh grant returns
	newID     string // the ID token a refresh grant returns
}

func newTMBEnv(t *testing.T, opts ...func(*TraefikOidc)) *tmbEnv {
	t.Helper()

	claims := map[string]interface{}{
		"sub": "user-1", "email": "u@example.com", "name": "U One",
		"groups": []interface{}{"admins"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"iat":    float64(time.Now().Unix()),
	}
	newClaims := map[string]interface{}{
		"sub": "user-1", "email": "u@example.com", "name": "U One",
		"groups": []interface{}{"admins"},
		"exp":    float64(time.Now().Add(2 * time.Hour).Unix()),
		"iat":    float64(time.Now().Unix()),
	}
	access := tokenWithGroups(t, claims)
	id := tokenWithGroups(t, claims)
	newAccess := tokenWithGroups(t, newClaims)
	newID := tokenWithGroups(t, newClaims)

	refreshBody, err := json.Marshal(map[string]interface{}{
		"access_token":  newAccess,
		"id_token":      newID,
		"refresh_token": tmbTestRotated,
		"expires_in":    7200,
	})
	require.NoError(t, err)
	idp := &tmbIdP{status: http.StatusOK, body: string(refreshBody)}
	srv := httptest.NewServer(idp)
	t.Cleanup(srv.Close)

	oidc := newTestOIDC(t, func(o *TraefikOidc) {
		o.tmbSessionURLPath = tmbPath
		o.tmbClaims = []string{"email", "name"}
		o.tokenCache = NewTokenCache()
		o.tokenVerifier = o // real VerifyToken; the seeded cache short-circuits it
		o.tokenExchanger = o
		o.extractClaimsFunc = extractClaims
		o.tokenURL = srv.URL + "/token"
		o.clientSecret = "secret"
		o.tokenHTTPClient = srv.Client()
		o.userIdentifierClaim = "sub"
		o.groupClaimName, o.roleClaimName = "groups", "roles"
		o.refreshGracePeriod = time.Minute
		o.allowedRolesAndGroups = map[string]struct{}{}
		o.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("token-mediating request must not reach the backend")
		})
	})
	for _, opt := range opts {
		opt(oidc)
	}
	seedVerified(t, oidc, access, claims)
	seedVerified(t, oidc, id, claims)
	seedVerified(t, oidc, newAccess, newClaims)
	seedVerified(t, oidc, newID, newClaims)

	base := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	rec := httptest.NewRecorder()
	session, err := oidc.sessionManager.GetSession(base)
	require.NoError(t, err)
	require.NoError(t, session.SetAuthenticated(true))
	session.SetAccessToken(access)
	session.SetIDToken(id)
	session.SetRefreshToken(tmbTestRefresh)
	session.SetUserIdentifier("user-1")
	require.NoError(t, session.Save(base, rec))

	return &tmbEnv{oidc: oidc, idp: idp, cookies: rec.Result().Cookies(), access: access, newAccess: newAccess, newID: newID}
}

func requestWithCookies(cs []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	for _, c := range cs {
		r.AddCookie(c)
	}
	return r
}

func (e *tmbEnv) do(method, path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://app.example.com"+path, nil)
	for _, c := range e.cookies {
		req.AddCookie(c)
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.oidc.ServeHTTP(rec, req)
	return rec
}

func (e *tmbEnv) get(path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	return e.do(http.MethodGet, path, mutate)
}

func (e *tmbEnv) post(path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	return e.do(http.MethodPost, path, mutate)
}

func decodeTMB(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), "body: %s", rec.Body.String())
	return m
}

func TestTMBGet_ReturnsSessionAndAccessToken(t *testing.T) {
	e := newTMBEnv(t)
	rec := e.get(tmbPath, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := decodeTMB(t, rec)
	assert.Equal(t, true, body["authenticated"])
	assert.Equal(t, "user-1", body["user_identifier"])
	assert.Equal(t, []interface{}{"admins"}, body["groups"])
	assert.Equal(t, map[string]interface{}{"email": "u@example.com", "name": "U One"}, body["claims"])
	assert.Contains(t, body, "expires_at")
	assert.Equal(t, e.access, body["access_token"])
	assert.InDelta(t, time.Now().Add(time.Hour).Unix(), body["expires_at"], 5, "the access token's expiry")
	assert.NotContains(t, body, "expires_in", "expiry is reported once, as an absolute time")
	assert.NotContains(t, rec.Body.String(), tmbTestRefresh, "the refresh token must never be returned")

	h := rec.Header()
	assert.Equal(t, "application/json", h.Get("Content-Type"))
	assert.Equal(t, "no-store", h.Get("Cache-Control"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "same-origin", h.Get("Cross-Origin-Resource-Policy"))
	assert.Empty(t, h.Get("Access-Control-Allow-Origin"))
	assert.Zero(t, e.idp.calls(), "GET does not call the IdP while the token is fresh")
}

// setRefreshResponse makes the fake token endpoint answer the next grants with
// the given access token and expires_in (the refreshed ID token is valid).
func (e *tmbEnv) setRefreshResponse(t *testing.T, accessToken string, expiresIn int) {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"access_token":  accessToken,
		"id_token":      e.newID,
		"refresh_token": tmbTestRotated,
		"expires_in":    expiresIn,
	})
	require.NoError(t, err)
	e.idp.mu.Lock()
	e.idp.body = string(body)
	e.idp.mu.Unlock()
}

func TestTMB_ReportsTheAccessTokenExpiry(t *testing.T) {
	t.Run("a session without a recorded expiry falls back to the token's exp claim", func(t *testing.T) {
		e := newTMBEnv(t)
		body := decodeTMB(t, e.get(tmbPath, nil))
		assert.InDelta(t, time.Now().Add(time.Hour).Unix(), body["expires_at"], 5)
	})
	t.Run("a recorded expiry wins over the token's exp claim", func(t *testing.T) {
		e := newTMBEnv(t)
		want := time.Now().Add(2 * time.Minute).Unix()
		session, err := e.oidc.sessionManager.GetSession(requestWithCookies(e.cookies))
		require.NoError(t, err)
		session.SetAccessTokenExpiresAt(session.GetAccessToken(), want)
		saved := httptest.NewRecorder()
		require.NoError(t, session.Save(requestWithCookies(e.cookies), saved))
		e.cookies = saved.Result().Cookies()

		body := decodeTMB(t, e.get(tmbPath, nil))
		assert.EqualValues(t, want, body["expires_at"], "the ID token and the JWT expire in an hour; the recorded value is used")
	})
	t.Run("POST reports the token response's expires_in and the next GET keeps it", func(t *testing.T) {
		e := newTMBEnv(t)
		e.setRefreshResponse(t, e.newAccess, 1800) // the refreshed JWT itself is good for 2 h
		rec := e.post(tmbPath, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeTMB(t, rec)
		assert.InDelta(t, time.Now().Add(30*time.Minute).Unix(), body["expires_at"], 5)

		next := requestWithCookies(e.cookies)
		for _, c := range rec.Result().Cookies() {
			next.AddCookie(c)
		}
		session, err := e.oidc.sessionManager.GetSession(next)
		require.NoError(t, err)
		assert.InDelta(t, time.Now().Add(30*time.Minute).Unix(), session.GetAccessTokenExpiresAt(), 5)
	})
	t.Run("an opaque access token gets its expiry from expires_in", func(t *testing.T) {
		e := newTMBEnv(t)
		e.setRefreshResponse(t, "opaque-access-token-0123456789abcdef", 1800)
		body := decodeTMB(t, e.post(tmbPath, nil))
		assert.Equal(t, "opaque-access-token-0123456789abcdef", body["access_token"])
		assert.InDelta(t, time.Now().Add(30*time.Minute).Unix(), body["expires_at"], 5)
	})
	t.Run("an opaque token with no expiry information reports none", func(t *testing.T) {
		e := newTMBEnv(t)
		e.setRefreshResponse(t, "opaque-access-token-0123456789abcdef", 0)
		body := decodeTMB(t, e.post(tmbPath, nil))
		assert.Equal(t, "opaque-access-token-0123456789abcdef", body["access_token"])
		assert.NotContains(t, body, "expires_at")
	})
}

// mutateSession rewrites the session behind the env's cookies.
func (e *tmbEnv) mutateSession(t *testing.T, fn func(*SessionData)) {
	t.Helper()
	session, err := e.oidc.sessionManager.GetSession(requestWithCookies(e.cookies))
	require.NoError(t, err)
	fn(session)
	saved := httptest.NewRecorder()
	require.NoError(t, session.Save(requestWithCookies(e.cookies), saved))
	e.cookies = saved.Result().Cookies()
}

// An opaque access token is judged by the ID token (valid for an hour here), so
// the plugin's own refresh logic keeps serving it; the endpoint hands out the
// access token and must look at the access token's own expiry.
func TestTMB_RefreshesAnAccessTokenThatIsDue(t *testing.T) {
	const opaque = "opaque-access-token-0123456789abcdef"
	setup := func(t *testing.T, remaining time.Duration, opts ...func(*SessionData)) *tmbEnv {
		e := newTMBEnv(t)
		e.mutateSession(t, func(sd *SessionData) {
			sd.SetAccessToken(opaque)
			sd.SetAccessTokenExpiresAt(opaque, time.Now().Add(remaining).Unix())
			for _, opt := range opts {
				opt(sd)
			}
		})
		return e
	}

	t.Run("a token with plenty of life left is served as is", func(t *testing.T) {
		e := setup(t, 30*time.Minute)
		rec := e.get(tmbPath, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, opaque, decodeTMB(t, rec)["access_token"])
		assert.Zero(t, e.idp.calls())
	})
	t.Run("one inside the grace window is refreshed before being returned", func(t *testing.T) {
		e := setup(t, 20*time.Second) // the env's grace period is one minute
		rec := e.get(tmbPath, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, e.newAccess, decodeTMB(t, rec)["access_token"])
		assert.Equal(t, 1, e.idp.calls())
		assert.Equal(t, "refresh_token", e.idp.last(t).Get("grant_type"))
	})
	t.Run("one that has already expired is refreshed too", func(t *testing.T) {
		e := setup(t, -10*time.Second)
		rec := e.get(tmbPath, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, e.newAccess, decodeTMB(t, rec)["access_token"])
	})
	t.Run("an expired token the IdP cannot refresh right now is never served", func(t *testing.T) {
		e := setup(t, -10*time.Second)
		e.idp.status, e.idp.body = http.StatusInternalServerError, `oops`
		rec := e.get(tmbPath, nil)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.Equal(t, "server_error", decodeTMB(t, rec)["error"])
		assert.NotContains(t, rec.Body.String(), "access_token")
	})
	t.Run("an expired token with no refresh token means logging in again", func(t *testing.T) {
		e := setup(t, -10*time.Second, func(sd *SessionData) { sd.SetRefreshToken("") })
		rec := e.get(tmbPath, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid_session", decodeTMB(t, rec)["error"])
		assert.NotContains(t, rec.Body.String(), "access_token")
		assert.Zero(t, e.idp.calls())
	})
	t.Run("an expired token whose refresh token is rejected ends the session", func(t *testing.T) {
		e := setup(t, -10*time.Second)
		e.idp.status, e.idp.body = http.StatusBadRequest, `{"error":"invalid_grant"}`
		rec := e.get(tmbPath, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid_session", decodeTMB(t, rec)["error"])
		assert.NotContains(t, rec.Body.String(), "access_token")
	})
	t.Run("a token due inside the grace window is still served if the refresh fails", func(t *testing.T) {
		e := setup(t, 20*time.Second)
		e.idp.status, e.idp.body = http.StatusInternalServerError, `oops`
		rec := e.get(tmbPath, nil)
		require.Equal(t, http.StatusOK, rec.Code, "the token is still valid, so the failed early refresh is not fatal")
		assert.Equal(t, opaque, decodeTMB(t, rec)["access_token"])
	})
}

func TestTMB_ClaimsAreOptIn(t *testing.T) {
	t.Run("nothing is returned by default", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.tmbClaims = nil })
		body := decodeTMB(t, e.get(tmbPath, nil))
		assert.NotContains(t, body, "claims")
		assert.Equal(t, "user-1", body["user_identifier"], "identity comes from userIdentifierClaim, not tmbClaims")
		assert.Equal(t, []interface{}{"admins"}, body["groups"], "groups come from groupClaimName, not tmbClaims")
	})
	t.Run("only listed claims, as they appear in the token", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.tmbClaims = []string{"groups", "email", "absent"} })
		body := decodeTMB(t, e.get(tmbPath, nil))
		assert.Equal(t, map[string]interface{}{
			"groups": []interface{}{"admins"},
			"email":  "u@example.com",
		}, body["claims"], "a non-scalar claim passes through; an absent claim is omitted; unlisted ones are not leaked")
	})
	t.Run("claims of a refreshed token are returned after POST", func(t *testing.T) {
		e := newTMBEnv(t)
		body := decodeTMB(t, e.post(tmbPath, nil))
		assert.Equal(t, map[string]interface{}{"email": "u@example.com", "name": "U One"}, body["claims"])
	})
}

func TestTMBGet_IgnoresParametersAndNeverForcesRefresh(t *testing.T) {
	e := newTMBEnv(t)
	rec := e.get(tmbPath+"?refresh=true&scope=read&resource="+url.QueryEscape("https://api.example.com"), nil)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, e.access, decodeTMB(t, rec)["access_token"])
	assert.Zero(t, e.idp.calls(), "a GET must have no side effect on the session")
}

func TestTMBPost_ForcesRefresh(t *testing.T) {
	e := newTMBEnv(t)
	rec := e.post(tmbPath, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := decodeTMB(t, rec)
	assert.Equal(t, e.newAccess, body["access_token"])
	assert.InDelta(t, time.Now().Add(2*time.Hour).Unix(), body["expires_at"], 5)
	assert.Equal(t, "user-1", body["user_identifier"], "POST returns the same body shape as GET")
	assert.Equal(t, []interface{}{"admins"}, body["groups"])

	require.Equal(t, 1, e.idp.calls())
	form := e.idp.last(t)
	assert.Equal(t, "refresh_token", form.Get("grant_type"))
	assert.Equal(t, tmbTestRefresh, form.Get("refresh_token"))
	assert.Empty(t, form.Get("scope"))

	// The refreshed tokens are persisted for later requests.
	next := requestWithCookies(e.cookies)
	for _, c := range rec.Result().Cookies() {
		next.AddCookie(c)
	}
	session, err := e.oidc.sessionManager.GetSession(next)
	require.NoError(t, err)
	assert.Equal(t, e.newAccess, session.GetAccessToken())
	assert.Equal(t, tmbTestRotated, session.GetRefreshToken())
}

func TestTMBPost_ErrorsAnswerWithoutLeakingTokens(t *testing.T) {
	t.Run("rejected refresh token ends the session", func(t *testing.T) {
		e := newTMBEnv(t)
		e.idp.status, e.idp.body = http.StatusBadRequest, `{"error":"invalid_grant"}`
		rec := e.post(tmbPath, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid_session", decodeTMB(t, rec)["error"])
		assert.NotContains(t, rec.Body.String(), "access_token")
	})
	t.Run("idp failure keeps the session and answers 502", func(t *testing.T) {
		e := newTMBEnv(t)
		e.idp.status, e.idp.body = http.StatusInternalServerError, `oops`
		rec := e.post(tmbPath, nil)

		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.Equal(t, "server_error", decodeTMB(t, rec)["error"])
		assert.NotContains(t, rec.Body.String(), "access_token")
		assert.Equal(t, http.StatusOK, e.get(tmbPath, nil).Code, "the session still works")
	})
	t.Run("no refresh token is backend_not_ready", func(t *testing.T) {
		e := newTMBEnv(t)
		session, err := e.oidc.sessionManager.GetSession(requestWithCookies(e.cookies))
		require.NoError(t, err)
		session.SetRefreshToken("")
		rec0 := httptest.NewRecorder()
		require.NoError(t, session.Save(requestWithCookies(e.cookies), rec0))
		e.cookies = rec0.Result().Cookies()

		rec := e.post(tmbPath, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "backend_not_ready", decodeTMB(t, rec)["error"])
		assert.Zero(t, e.idp.calls())
	})
}

func TestTMB_NoSessionIsInvalidSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		e := newTMBEnv(t)
		e.cookies = nil
		rec := e.do(method, tmbPath, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, method)
		assert.Equal(t, "invalid_session", decodeTMB(t, rec)["error"], method)
		assert.Empty(t, rec.Header().Get("Location"), "must not redirect")
		assert.Zero(t, e.idp.calls())
	}
}

func TestTMB_RejectsOtherMethods(t *testing.T) {
	e := newTMBEnv(t)
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodHead} {
		rec := e.do(m, tmbPath, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, m)
		assert.Equal(t, "GET, POST", rec.Header().Get("Allow"), m)
	}
	assert.Zero(t, e.idp.calls())
}

func TestTMB_CrossOriginRequestsRejected(t *testing.T) {
	e := newTMBEnv(t)
	cases := map[string]func(*http.Request){
		"sec-fetch cross-site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"sec-fetch same-site":  func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
		"foreign origin":       func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"null origin":          func(r *http.Request) { r.Header.Set("Origin", "null") },
	}
	for name, mutate := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := e.do(method, tmbPath, mutate)
			assert.Equal(t, http.StatusForbidden, rec.Code, name+" "+method)
		}
	}
	assert.Zero(t, e.idp.calls(), "a cross-origin request must not trigger a refresh")
	for name, mutate := range map[string]func(*http.Request){
		"same-origin fetch":  func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
		"same origin header": func(r *http.Request) { r.Header.Set("Origin", "https://app.example.com") },
		"address bar":        func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") },
	} {
		assert.Equal(t, http.StatusOK, e.get(tmbPath, mutate).Code, name)
	}
}

func TestTMB_ConfiguredPathEnablesEndpoint(t *testing.T) {
	t.Run("unset path leaves the endpoint off", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.tmbSessionURLPath = "" })
		for _, p := range []string{tmbPath, ""} {
			assert.False(t, e.oidc.isTMBPath(p), p)
		}
	})
	t.Run("custom path is served and others are not", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.tmbSessionURLPath = "/api/me" })
		rec := e.get("/api/me", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, e.access, decodeTMB(t, rec)["access_token"])
		assert.False(t, e.oidc.isTMBPath(tmbPath))
	})
}

func TestConfigValidate_TMBPath(t *testing.T) {
	valid := func() *Config {
		c := CreateConfig()
		c.ProviderURL = "https://provider.example.com"
		c.ClientID = "id"
		c.ClientSecret = "secret"
		c.CallbackURL = "/callback"
		c.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
		return c
	}
	require.NoError(t, valid().Validate())

	ok := valid()
	ok.TMBSessionURL = tmbPath
	require.NoError(t, ok.Validate())

	cases := map[string]func(*Config){
		"no leading slash":                       func(c *Config) { c.TMBSessionURL = "session" },
		"query":                                  func(c *Config) { c.TMBSessionURL = "/s?x=1" },
		"fragment":                               func(c *Config) { c.TMBSessionURL = "/s#x" },
		"equals callback":                        func(c *Config) { c.TMBSessionURL = "/callback" },
		"equals logout":                          func(c *Config) { c.LogoutURL = "/out"; c.TMBSessionURL = "/out" },
		"empty claim name":                       func(c *Config) { c.TMBClaims = []string{"email", ""} },
		"equals the derived default logout path": func(c *Config) { c.TMBSessionURL = "/callback/logout" },
		"equals back-channel path, written without a slash": func(c *Config) {
			c.BackchannelLogoutURL, c.TMBSessionURL = "bc/logout", "/bc/logout"
		},
		"equals front-channel path": func(c *Config) {
			c.FrontchannelLogoutURL, c.TMBSessionURL = "/fc/logout", "/fc/logout"
		},
		"leading //": func(c *Config) { c.TMBSessionURL = "//auth/session" },
		"backslash":  func(c *Config) { c.TMBSessionURL = "/auth\\session" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(c)
			assert.Error(t, c.Validate())
		})
	}
}

// The endpoint authenticates itself, so none of the bypasses may forward a
// request on its path to the backend (newTMBEnv's next fails the test).
func TestTMB_NoBypassForwardsToBackend(t *testing.T) {
	cases := map[string]struct {
		opt    func(*TraefikOidc)
		mutate func(*http.Request)
		method string
	}{
		"excluded URL": {
			opt:    func(o *TraefikOidc) { o.excludedURLs = map[string]struct{}{tmbPath: {}} },
			method: http.MethodGet,
		},
		"SSE accept header": {
			mutate: func(r *http.Request) { r.Header.Set("Accept", "text/event-stream") },
			method: http.MethodGet,
		},
		"WebSocket upgrade": {
			mutate: func(r *http.Request) {
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "Upgrade")
			},
			method: http.MethodGet,
		},
		"unauthenticated preflight allowed": {
			opt: func(o *TraefikOidc) { o.allowUnauthenticatedPreflight = true },
			mutate: func(r *http.Request) {
				r.Header.Set("Origin", "https://app.example.com")
				r.Header.Set("Access-Control-Request-Method", "POST")
			},
			method: http.MethodOptions,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var opts []func(*TraefikOidc)
			if c.opt != nil {
				opts = append(opts, c.opt)
			}
			e := newTMBEnv(t, opts...)
			rec := e.do(c.method, tmbPath, c.mutate)
			if c.method == http.MethodOptions {
				assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
				return
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, e.access, decodeTMB(t, rec)["access_token"])
		})
	}
}

func TestTMBPost_SharesThePerSourceThrottle(t *testing.T) {
	t.Run("forced refreshes are limited, reads are not", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.perSourceLimiter = newPerSourceAuthLimiter(2) })
		assert.Equal(t, http.StatusOK, e.post(tmbPath, nil).Code)
		assert.Equal(t, http.StatusOK, e.post(tmbPath, nil).Code)
		callsBefore := e.idp.calls()

		rec := e.post(tmbPath, nil)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "rate_limited", decodeTMB(t, rec)["error"])
		assert.Equal(t, "1", rec.Header().Get("Retry-After"))
		assert.NotContains(t, rec.Body.String(), "access_token")
		assert.Equal(t, callsBefore, e.idp.calls(), "a throttled POST must not reach the IdP")

		assert.Equal(t, http.StatusOK, e.get(tmbPath, nil).Code, "GET stays available while throttled")
	})
	t.Run("no limiter configured means no throttling", func(t *testing.T) {
		e := newTMBEnv(t)
		for i := 0; i < 5; i++ {
			assert.Equal(t, http.StatusOK, e.post(tmbPath, nil).Code)
		}
	})
	t.Run("internal sources are never throttled", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.perSourceLimiter = newPerSourceAuthLimiter(1) })
		for i := 0; i < 3; i++ {
			rec := e.post(tmbPath, func(r *http.Request) { r.RemoteAddr = "10.1.2.3:4567" })
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})
}

func TestTMB_NeverEmitsCORSHeaders(t *testing.T) {
	e := newTMBEnv(t, func(o *TraefikOidc) {
		// What securityHeaders.corsEnabled does at the top of ServeHTTP.
		o.securityHeadersApplier = func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Access-Control-Allow-Origin", "https://evil.example")
			rw.Header().Set("Access-Control-Allow-Credentials", "true")
			rw.Header().Set("access-control-allow-headers", "x-anything")
			rw.Header().Set("X-Frame-Options", "DENY")
		}
	})
	for _, rec := range []*httptest.ResponseRecorder{
		e.get(tmbPath, nil),
		e.post(tmbPath, nil),
		e.get(tmbPath, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }),
		e.do(http.MethodPut, tmbPath, nil),
	} {
		for name := range rec.Header() {
			assert.NotContains(t, name, "Access-Control", "response %d", rec.Code)
		}
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"), "unrelated security headers are kept")
	}
}

func TestTMB_AuthorizationGates(t *testing.T) {
	t.Run("user not in allowlist", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.allowedUsers = map[string]struct{}{"someone-else": {}} })
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := e.do(method, tmbPath, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code, method)
			assert.Equal(t, "access_denied", decodeTMB(t, rec)["error"])
			assert.NotContains(t, rec.Body.String(), "access_token")
		}
		assert.Zero(t, e.idp.calls(), "an unauthorized user must not trigger a refresh")
	})
	t.Run("missing required group", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.allowedRolesAndGroups = map[string]struct{}{"staff": {}} })
		assert.Equal(t, http.StatusForbidden, e.get(tmbPath, nil).Code)
		assert.Equal(t, http.StatusForbidden, e.post(tmbPath, nil).Code)
		assert.Zero(t, e.idp.calls(), "an unauthorized user must not trigger a refresh")
	})
	t.Run("required group present", func(t *testing.T) {
		e := newTMBEnv(t, func(o *TraefikOidc) { o.allowedRolesAndGroups = map[string]struct{}{"admins": {}} })
		assert.Equal(t, http.StatusOK, e.get(tmbPath, nil).Code)
		assert.Equal(t, http.StatusOK, e.post(tmbPath, nil).Code)
	})
}

func TestTMB_BearerHeaderDoesNotBypassSessionCheck(t *testing.T) {
	e := newTMBEnv(t, func(o *TraefikOidc) { o.enableBearerAuth = true })
	e.cookies = nil
	rec := e.get(tmbPath, func(r *http.Request) { r.Header.Set("Authorization", "Bearer a.b.c") })

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "invalid_session", decodeTMB(t, rec)["error"])
}
