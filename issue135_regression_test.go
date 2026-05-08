package traefikoidc

// issue135_regression_test.go — regression tests for RFC 7523 private_key_jwt
// client authentication (issue #135).
//
// These tests guard:
//   - Correct JWT construction and cryptographic signature for all supported
//     algorithms (RS*/PS*/ES*).
//   - Proper validation of alg/key type combinations and empty-kid rejection.
//   - JTI uniqueness across concurrent calls.
//   - PEM variant tolerance (PKCS#8, PKCS#1, SEC1).
//   - Config.Validate() behavior for all private_key_jwt configuration paths.
//   - buildClientAssertionSignerFromConfig: inline PEM, file-backed PEM, default alg.
//   - Wire-up in exchangeTokens: assertion fields sent, client_secret absent.
//   - Wire-up in RevokeTokenWithProvider: assertion fields sent, audience = tokenURL.
//   - Back-compat: client_secret_post path unchanged when clientAssertion == nil.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── A. Signer unit tests ──────────────────────────────────────────────────────

// TestIssue135_SignerRSAFamily verifies that NewClientAssertionSigner + Sign
// produces a well-formed, cryptographically valid JWT for every RSA-family
// algorithm (RS256/RS384/RS512/PS256/PS384/PS512).
func TestIssue135_SignerRSAFamily(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	cases := []struct {
		alg      string
		hashFn   func([]byte) []byte
		isPS     bool
		hash     crypto.Hash
	}{
		{"RS256", func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, false, crypto.SHA256},
		{"RS384", func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, false, crypto.SHA384},
		{"RS512", func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, false, crypto.SHA512},
		{"PS256", func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, true, crypto.SHA256},
		{"PS384", func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, true, crypto.SHA384},
		{"PS512", func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, true, crypto.SHA512},
	}

	const (
		audience = "https://example.com/token"
		clientID = "client-abc"
		kid      = "kid-1"
	)

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			signer, err := NewClientAssertionSigner(pemBytes, tc.alg, kid)
			require.NoError(t, err)

			jwtStr, err := signer.Sign(audience, clientID)
			require.NoError(t, err)

			parts := strings.Split(jwtStr, ".")
			require.Len(t, parts, 3, "JWT must have three dot-separated parts")

			// Decode and check header.
			hdr := decodeJSONPart(t, parts[0])
			assert.Equal(t, tc.alg, hdr["alg"])
			assert.Equal(t, "JWT", hdr["typ"])
			assert.Equal(t, kid, hdr["kid"])

			// Decode and check claims.
			clms := decodeJSONPart(t, parts[1])
			assert.Equal(t, clientID, clms["iss"])
			assert.Equal(t, clientID, clms["sub"])
			assert.Equal(t, audience, clms["aud"])

			iat, ok := clms["iat"].(float64)
			require.True(t, ok, "iat must be numeric")
			exp, ok := clms["exp"].(float64)
			require.True(t, ok, "exp must be numeric")
			assert.InDelta(t, 60, exp-iat, 2, "exp-iat must equal ~60s")

			now := float64(time.Now().Unix())
			assert.True(t, iat <= now+2 && iat >= now-5, "iat must be current time ±5s")

			jti, ok := clms["jti"].(string)
			require.True(t, ok, "jti must be a string")
			assert.Len(t, jti, 32, "jti must be 32-char hex (16 bytes → hex)")

			// Verify cryptographic signature.
			sigInput := parts[0] + "." + parts[1]
			digest := tc.hashFn([]byte(sigInput))
			sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
			require.NoError(t, err)

			pub := &rsaKey.PublicKey
			if tc.isPS {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: tc.hash}
				assert.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sigBytes, opts),
					"PSS signature verification failed for %s", tc.alg)
			} else {
				assert.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sigBytes),
					"PKCS1v15 signature verification failed for %s", tc.alg)
			}
		})
	}
}

// TestIssue135_SignerECDSAFamily verifies correct JWT production for all
// ECDSA algorithms (ES256/ES384/ES512) including that the signature is the
// raw r||s encoding (not ASN.1 DER) and is verifiable with the matching key.
func TestIssue135_SignerECDSAFamily(t *testing.T) {
	cases := []struct {
		alg    string
		curve  elliptic.Curve
		hashFn func([]byte) []byte
		hash   crypto.Hash
	}{
		{"ES256", elliptic.P256(), func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, crypto.SHA256},
		{"ES384", elliptic.P384(), func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, crypto.SHA384},
		{"ES512", elliptic.P521(), func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, crypto.SHA512},
	}

	const (
		audience = "https://idp.example.com/token"
		clientID = "ec-client"
		kid      = "ec-kid"
	)

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			pemBytes := encodeECPKCS8(t, ecKey)

			signer, err := NewClientAssertionSigner(pemBytes, tc.alg, kid)
			require.NoError(t, err)

			jwtStr, err := signer.Sign(audience, clientID)
			require.NoError(t, err)

			parts := strings.Split(jwtStr, ".")
			require.Len(t, parts, 3)

			sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
			require.NoError(t, err)

			byteLen := (tc.curve.Params().BitSize + 7) / 8
			assert.Len(t, sigBytes, 2*byteLen,
				"ECDSA signature must be raw r||s (2×%d bytes for %s)", byteLen, tc.alg)

			r := new(big.Int).SetBytes(sigBytes[:byteLen])
			s := new(big.Int).SetBytes(sigBytes[byteLen:])

			sigInput := parts[0] + "." + parts[1]
			digest := tc.hashFn([]byte(sigInput))

			ok := ecdsa.Verify(&ecKey.PublicKey, digest, r, s)
			assert.True(t, ok, "ECDSA signature verification failed for %s", tc.alg)
		})
	}
}

// TestIssue135_SignerRejectsAlgKeyMismatch verifies that the signer constructor
// rejects type mismatches between key type and algorithm, unknown algorithms,
// and an empty kid.
func TestIssue135_SignerRejectsAlgKeyMismatch(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	rsaPEM := encodeRSAPKCS8(t, rsaKey)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPEM := encodeECPKCS8(t, ecKey)

	cases := []struct {
		name     string
		pemBytes []byte
		alg      string
		kid      string
		wantErr  string
	}{
		{
			name:    "RSA key with ES256",
			pemBytes: rsaPEM,
			alg:     "ES256",
			kid:     "k1",
			wantErr: "EC key",
		},
		{
			name:    "EC key with RS256",
			pemBytes: ecPEM,
			alg:     "RS256",
			kid:     "k1",
			wantErr: "RSA key",
		},
		{
			name:    "unknown alg HS256",
			pemBytes: rsaPEM,
			alg:     "HS256",
			kid:     "k1",
			wantErr: "unsupported",
		},
		{
			name:    "empty kid",
			pemBytes: rsaPEM,
			alg:     "RS256",
			kid:     "",
			wantErr: "kid must not be empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClientAssertionSigner(tc.pemBytes, tc.alg, tc.kid)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantErr),
				"error should mention %q", tc.wantErr)
		})
	}
}

// TestIssue135_SignerJTIUniqueness signs 50 assertions with the same signer
// and asserts all jti values are distinct. Guards against broken entropy reuse.
func TestIssue135_SignerJTIUniqueness(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	signer, err := NewClientAssertionSigner(pemBytes, "RS256", "jti-kid")
	require.NoError(t, err)

	seen := make(map[string]bool, 50)
	for i := range 50 {
		jwtStr, err := signer.Sign("https://example.com/token", "client-x")
		require.NoError(t, err)

		parts := strings.Split(jwtStr, ".")
		require.Len(t, parts, 3)
		clms := decodeJSONPart(t, parts[1])
		jti, ok := clms["jti"].(string)
		require.True(t, ok)
		assert.False(t, seen[jti], "jti %q was reused at iteration %d", jti, i)
		seen[jti] = true
	}
}

// TestIssue135_SignerPEMVariants confirms that all PEM block types understood
// by NewClientAssertionSigner are parsed correctly: PKCS#8 ("PRIVATE KEY"),
// PKCS#1 ("RSA PRIVATE KEY"), and SEC1 ("EC PRIVATE KEY").
func TestIssue135_SignerPEMVariants(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("RSA PKCS8", func(t *testing.T) {
		pemBytes := encodeRSAPKCS8(t, rsaKey)
		signer, err := NewClientAssertionSigner(pemBytes, "RS256", "k1")
		require.NoError(t, err)
		assertValidRSAJWT(t, rsaKey, signer, "RS256")
	})

	t.Run("RSA PKCS1", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		signer, err := NewClientAssertionSigner(pemBytes, "RS256", "k1")
		require.NoError(t, err)
		assertValidRSAJWT(t, rsaKey, signer, "RS256")
	})

	t.Run("EC PKCS8", func(t *testing.T) {
		pemBytes := encodeECPKCS8(t, ecKey)
		signer, err := NewClientAssertionSigner(pemBytes, "ES256", "k1")
		require.NoError(t, err)
		jwtStr, err := signer.Sign("https://example.com/token", "cid")
		require.NoError(t, err)
		parts := strings.Split(jwtStr, ".")
		require.Len(t, parts, 3)
	})

	t.Run("EC SEC1", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(ecKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		signer, err := NewClientAssertionSigner(pemBytes, "ES256", "k1")
		require.NoError(t, err)
		jwtStr, err := signer.Sign("https://example.com/token", "cid")
		require.NoError(t, err)
		parts := strings.Split(jwtStr, ".")
		require.Len(t, parts, 3)
	})
}

// ── B. Config validation ──────────────────────────────────────────────────────

// TestIssue135_ConfigValidation table-drives Config.Validate() for every
// client-authentication-related validation branch.
func TestIssue135_ConfigValidation(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	validPEM := string(encodeRSAPKCS8(t, rsaKey))

	// baseConfig returns the minimum valid config, modified per test case.
	base := func() *Config {
		return &Config{
			ProviderURL:          "https://idp.example.com",
			CallbackURL:          "/cb",
			ClientID:             "cid",
			ClientSecret:         "secret",
			SessionEncryptionKey: "01234567890123456789012345678901", // 32 chars
			RateLimit:            100,
		}
	}

	cases := []struct {
		name     string
		mutate   func(*Config)
		wantErr  string // empty = expect nil error
	}{
		{
			name:    "default empty method + secret ok",
			mutate:  func(c *Config) { /* nothing extra */ },
			wantErr: "",
		},
		{
			name: "explicit client_secret_post + secret ok",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "client_secret_post"
			},
			wantErr: "",
		},
		{
			name: "private_key_jwt inline key + kid ok",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "private_key_jwt"
				c.ClientSecret = ""
				c.ClientAssertionPrivateKey = validPEM
				c.ClientAssertionKeyID = "k1"
			},
			wantErr: "",
		},
		{
			name: "private_key_jwt no key at all",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "private_key_jwt"
				c.ClientSecret = ""
				c.ClientAssertionKeyID = "k1"
			},
			wantErr: "clientAssertionPrivateKey",
		},
		{
			name: "private_key_jwt both inline and path",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "private_key_jwt"
				c.ClientSecret = ""
				c.ClientAssertionPrivateKey = validPEM
				c.ClientAssertionKeyPath = "/tmp/key.pem"
				c.ClientAssertionKeyID = "k1"
			},
			wantErr: "only one of",
		},
		{
			name: "private_key_jwt key but no kid",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "private_key_jwt"
				c.ClientSecret = ""
				c.ClientAssertionPrivateKey = validPEM
			},
			wantErr: "clientAssertionKeyID",
		},
		{
			name: "private_key_jwt unsupported alg HS256",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "private_key_jwt"
				c.ClientSecret = ""
				c.ClientAssertionPrivateKey = validPEM
				c.ClientAssertionKeyID = "k1"
				c.ClientAssertionAlg = "HS256"
			},
			wantErr: "is not supported",
		},
		{
			name: "unknown client auth method",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "weird"
			},
			wantErr: "is not supported",
		},
		{
			name: "client_secret_post with no secret",
			mutate: func(c *Config) {
				c.ClientAuthMethod = "client_secret_post"
				c.ClientSecret = ""
			},
			wantErr: "clientSecret is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr,
					"error must mention %q", tc.wantErr)
			}
		})
	}
}

// TestIssue135_ConfigKeyPathLoadsFile verifies that buildClientAssertionSignerFromConfig
// reads the PEM key from disk when ClientAssertionKeyPath is set.
func TestIssue135_ConfigKeyPathLoadsFile(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	dir := t.TempDir()
	keyFile := dir + "/private.pem"
	require.NoError(t, os.WriteFile(keyFile, pemBytes, 0o600))

	cfg := &Config{
		ClientAuthMethod:    "private_key_jwt",
		ClientAssertionKeyPath: keyFile,
		ClientAssertionKeyID:   "file-kid",
		ClientAssertionAlg:     "RS256",
	}

	signer, err := buildClientAssertionSignerFromConfig(cfg)
	require.NoError(t, err, "should load signer from key file")
	require.NotNil(t, signer)

	// Confirm signer produces a valid JWT.
	jwtStr, err := signer.Sign("https://example.com/token", "client-from-file")
	require.NoError(t, err)
	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3, "should produce a 3-part JWT")
}

// ── C. Wire-up — exchangeTokens ───────────────────────────────────────────────

// TestIssue135_AuthCodeExchangeUsesAssertion confirms that exchangeTokens sends
// client_assertion + client_assertion_type instead of client_secret when a
// ClientAssertionSigner is configured, and that the assertion JWT is valid.
func TestIssue135_AuthCodeExchangeUsesAssertion(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		capturedBody = body
		w.Header().Set("Content-Type", "application/json")
		// Return a minimal token response so exchangeTokens doesn't error.
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "at",
			IDToken:      "it",
			RefreshToken: "rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	signer, err := NewClientAssertionSigner(pemBytes, "RS256", "wire-kid")
	require.NoError(t, err)

	oidc := &TraefikOidc{
		clientID:        "wire-client",
		tokenHTTPClient: server.Client(),
		clientAssertion: signer,
		logger:          GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = server.URL

	_, err = oidc.exchangeTokens(context.Background(), "authorization_code", "code-x", "https://app/cb", "")
	require.NoError(t, err)

	form, err := url.ParseQuery(string(capturedBody))
	require.NoError(t, err)

	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		form.Get("client_assertion_type"), "client_assertion_type must be set")
	assertionJWT := form.Get("client_assertion")
	assert.NotEmpty(t, assertionJWT, "client_assertion must be present")
	assert.Empty(t, form.Get("client_secret"), "client_secret must not be sent when using assertion")
	assert.Equal(t, "wire-client", form.Get("client_id"))
	assert.Equal(t, "code-x", form.Get("code"))
	assert.Equal(t, "authorization_code", form.Get("grant_type"))

	// Verify assertion JWT: header, claims, signature.
	parts := strings.Split(assertionJWT, ".")
	require.Len(t, parts, 3)

	hdr := decodeJSONPart(t, parts[0])
	assert.Equal(t, "RS256", hdr["alg"])

	clms := decodeJSONPart(t, parts[1])
	assert.Equal(t, "wire-client", clms["iss"])
	assert.Equal(t, "wire-client", clms["sub"])
	assert.Equal(t, server.URL, clms["aud"],
		"audience must be the tokenURL (RFC 7523 §3)")

	// Verify signature with RSA public key.
	sigInput := parts[0] + "." + parts[1]
	digest := sha256SumBytes([]byte(sigInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest, sigBytes))
}

// TestIssue135_RefreshTokenUsesAssertion verifies that the refresh_token grant
// type also sends client_assertion and the correct form fields.
func TestIssue135_RefreshTokenUsesAssertion(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "new-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	signer, err := NewClientAssertionSigner(pemBytes, "RS256", "rt-kid")
	require.NoError(t, err)

	oidc := &TraefikOidc{
		clientID:        "rt-client",
		tokenHTTPClient: server.Client(),
		clientAssertion: signer,
		logger:          GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = server.URL

	_, err = oidc.exchangeTokens(context.Background(), "refresh_token", "rt-y", "", "")
	require.NoError(t, err)

	assert.Equal(t, "refresh_token", capturedForm.Get("grant_type"))
	assert.Equal(t, "rt-y", capturedForm.Get("refresh_token"))
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		capturedForm.Get("client_assertion_type"))
	assert.NotEmpty(t, capturedForm.Get("client_assertion"))
	assert.Empty(t, capturedForm.Get("client_secret"))
}

// TestIssue135_BackcompatClientSecretPath confirms that exchangeTokens sends
// client_secret and does NOT send client_assertion when clientAssertion is nil.
func TestIssue135_BackcompatClientSecretPath(t *testing.T) {
	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	oidc := &TraefikOidc{
		clientID:        "legacy-client",
		clientSecret:    "legacy-secret",
		tokenHTTPClient: server.Client(),
		clientAssertion: nil, // back-compat path
		logger:          GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = server.URL

	_, err := oidc.exchangeTokens(context.Background(), "authorization_code", "code-bc", "https://app/cb", "")
	require.NoError(t, err)

	assert.Equal(t, "legacy-secret", capturedForm.Get("client_secret"),
		"client_secret must be sent on the classic path")
	assert.Empty(t, capturedForm.Get("client_assertion"),
		"client_assertion must NOT be present on the classic path")
	assert.Empty(t, capturedForm.Get("client_assertion_type"),
		"client_assertion_type must NOT be present on the classic path")
}

// TestIssue135_ClientSecretBasicAuth verifies that when clientAuthMethod is
// "client_secret_basic", exchangeTokens sends an HTTP Basic Authorization
// header carrying url-encoded client_id:client_secret per RFC 6749 §2.3.1,
// and that neither client_id nor client_secret appears in the form body.
func TestIssue135_ClientSecretBasicAuth(t *testing.T) {
	var capturedAuth string
	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "at-basic", TokenType: "Bearer", ExpiresIn: 3600,
		})
	}))
	defer server.Close()

	oidc := &TraefikOidc{
		clientID:         "basic-client",
		clientSecret:     "basic-secret",
		clientAuthMethod: "client_secret_basic",
		tokenHTTPClient:  server.Client(),
		logger:           GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = server.URL

	_, err := oidc.exchangeTokens(context.Background(), "authorization_code", "code-bb", "https://app/cb", "")
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(capturedAuth, "Basic "),
		"Authorization header must start with 'Basic ', got %q", capturedAuth)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(capturedAuth, "Basic "))
	require.NoError(t, err, "Authorization payload must be valid base64")
	user, pass, ok := strings.Cut(string(raw), ":")
	require.True(t, ok, "Authorization payload must contain a single ':' separator")
	assert.Equal(t, "basic-client", user, "client_id should round-trip through QueryEscape")
	assert.Equal(t, "basic-secret", pass, "client_secret should round-trip through QueryEscape")

	assert.Empty(t, capturedForm.Get("client_id"),
		"client_id must NOT be in the body when using client_secret_basic")
	assert.Empty(t, capturedForm.Get("client_secret"),
		"client_secret must NOT be in the body when using client_secret_basic")
	assert.Empty(t, capturedForm.Get("client_assertion"),
		"client_assertion must NOT be present on the basic-auth path")
}

// TestIssue135_ClientSecretBasicURLEncodesReservedChars verifies that
// credentials containing reserved characters (`:`, `+`, `/`, etc.) are
// form-urlencoded before base64 per RFC 6749 §2.3.1, so the receiving
// authorization server can decode them deterministically.
func TestIssue135_ClientSecretBasicURLEncodesReservedChars(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer server.Close()

	const (
		clientID     = "weird:id+1"
		clientSecret = "p@ss/word=&" //nolint:gosec // test fixture
	)

	oidc := &TraefikOidc{
		clientID:         clientID,
		clientSecret:     clientSecret,
		clientAuthMethod: "client_secret_basic",
		tokenHTTPClient:  server.Client(),
		logger:           GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = server.URL

	_, err := oidc.exchangeTokens(context.Background(), "authorization_code", "c", "https://app/cb", "")
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(capturedAuth, "Basic "))
	require.NoError(t, err)

	wantUser := url.QueryEscape(clientID)
	wantPass := url.QueryEscape(clientSecret)
	assert.Equal(t, wantUser+":"+wantPass, string(raw),
		"both halves must be form-urlencoded before the base64 step")
}

// TestIssue135_ClientSecretBasicRevocation verifies that the revocation path
// honors client_secret_basic identically to the token path.
func TestIssue135_ClientSecretBasicRevocation(t *testing.T) {
	var capturedAuth string
	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oidc := &TraefikOidc{
		clientID:         "rev-basic",
		clientSecret:     "rev-secret",
		clientAuthMethod: "client_secret_basic",
		httpClient:       server.Client(),
		logger:           GetSingletonNoOpLogger(),
	}
	oidc.tokenURL = "https://idp.example.com/token"
	oidc.revocationURL = server.URL

	require.NoError(t, oidc.RevokeTokenWithProvider("opaque-tok", "access_token"))

	require.True(t, strings.HasPrefix(capturedAuth, "Basic "), "got %q", capturedAuth)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(capturedAuth, "Basic "))
	require.NoError(t, err)
	assert.Equal(t, "rev-basic:rev-secret", string(raw))

	assert.Equal(t, "opaque-tok", capturedForm.Get("token"))
	assert.Equal(t, "access_token", capturedForm.Get("token_type_hint"))
	assert.Empty(t, capturedForm.Get("client_id"),
		"client_id must NOT be in body on Basic-auth revocation")
	assert.Empty(t, capturedForm.Get("client_secret"),
		"client_secret must NOT be in body on Basic-auth revocation")
}

// ── D. Wire-up — RevokeTokenWithProvider ────────────────────────────────────

// TestIssue135_RevocationUsesAssertion verifies that RevokeTokenWithProvider
// sends client_assertion (not client_secret), and that the assertion's audience
// is the tokenURL, not the revocationURL (per RFC 7523 §3).
func TestIssue135_RevocationUsesAssertion(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	const (
		tokenEndpoint      = "https://idp.example.com/token"  // audience for assertion
		clientIDVal        = "revoke-client"
	)

	var capturedForm url.Values
	// Revocation endpoint — deliberate separate URL to confirm audience != revocationURL.
	revokeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form
		w.WriteHeader(http.StatusOK)
	}))
	defer revokeServer.Close()

	signer, err := NewClientAssertionSigner(pemBytes, "RS256", "rev-kid")
	require.NoError(t, err)

	oidc := &TraefikOidc{
		clientID:        clientIDVal,
		clientAssertion: signer,
		httpClient:      revokeServer.Client(),
		logger:          GetSingletonNoOpLogger(),
	}
	// tokenURL drives assertion audience; revocationURL is where the POST goes.
	oidc.tokenURL = tokenEndpoint
	oidc.revocationURL = revokeServer.URL

	err = oidc.RevokeTokenWithProvider("some-token", "refresh_token")
	require.NoError(t, err)

	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		capturedForm.Get("client_assertion_type"))
	assertionJWT := capturedForm.Get("client_assertion")
	assert.NotEmpty(t, assertionJWT)
	assert.Empty(t, capturedForm.Get("client_secret"),
		"client_secret must not appear in revocation request with assertion")

	// Verify the assertion audience is tokenURL (not revocationURL).
	parts := strings.Split(assertionJWT, ".")
	require.Len(t, parts, 3)
	clms := decodeJSONPart(t, parts[1])
	assert.Equal(t, tokenEndpoint, clms["aud"],
		"assertion audience must be tokenURL, not revocationURL")

	// Sanity-check cryptographic validity.
	sigInput := parts[0] + "." + parts[1]
	digest := sha256SumBytes([]byte(sigInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest, sigBytes))
}

// ── E. End-to-end via buildClientAssertionSignerFromConfig ───────────────────

// TestIssue135_BuildSignerFromInlineConfig confirms that the full config→signer
// pipeline works for an ES256 key specified inline in the Config struct.
func TestIssue135_BuildSignerFromInlineConfig(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes := encodeECPKCS8(t, ecKey)

	cfg := &Config{
		ClientAuthMethod:          "private_key_jwt",
		ClientAssertionPrivateKey: string(pemBytes),
		ClientAssertionKeyID:      "inline-ec-kid",
		ClientAssertionAlg:        "ES256",
	}

	signer, err := buildClientAssertionSignerFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, signer)

	jwtStr, err := signer.Sign("https://example.com/token", "inline-client")
	require.NoError(t, err)

	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3)

	hdr := decodeJSONPart(t, parts[0])
	assert.Equal(t, "ES256", hdr["alg"])
	assert.Equal(t, "inline-ec-kid", hdr["kid"])

	// Verify the EC signature.
	byteLen := (elliptic.P256().Params().BitSize + 7) / 8
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sigBytes, 2*byteLen)

	r := new(big.Int).SetBytes(sigBytes[:byteLen])
	s := new(big.Int).SetBytes(sigBytes[byteLen:])
	sigInput := parts[0] + "." + parts[1]
	digest := sha256SumBytes([]byte(sigInput))
	assert.True(t, ecdsa.Verify(&ecKey.PublicKey, digest, r, s))
}

// TestIssue135_BuildSignerDefaultsToRS256 verifies that an empty
// ClientAssertionAlg defaults to RS256.
func TestIssue135_BuildSignerDefaultsToRS256(t *testing.T) {
	rsaKey := genRSAKey(t, 2048)
	pemBytes := encodeRSAPKCS8(t, rsaKey)

	cfg := &Config{
		ClientAssertionPrivateKey: string(pemBytes),
		ClientAssertionKeyID:      "default-alg-kid",
		ClientAssertionAlg:        "", // intentionally empty
	}

	signer, err := buildClientAssertionSignerFromConfig(cfg)
	require.NoError(t, err)

	jwtStr, err := signer.Sign("https://example.com/token", "default-client")
	require.NoError(t, err)

	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3)

	hdr := decodeJSONPart(t, parts[0])
	assert.Equal(t, "RS256", hdr["alg"], "empty alg must default to RS256")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// genRSAKey generates an RSA key of the given bit size, failing the test on error.
func genRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return k
}

// encodeRSAPKCS8 marshals an RSA key as PKCS#8 PEM ("PRIVATE KEY").
func encodeRSAPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// encodeECPKCS8 marshals an EC key as PKCS#8 PEM ("PRIVATE KEY").
func encodeECPKCS8(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// decodeJSONPart base64url-decodes a JWT part and parses it as a JSON object.
func decodeJSONPart(t *testing.T, b64url string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(b64url)
	require.NoError(t, err, "base64url decode of JWT part failed")
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m), "JSON unmarshal of JWT part failed")
	return m
}

// sha256SumBytes returns the SHA-256 digest of b as a byte slice.
func sha256SumBytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// assertValidRSAJWT signs a JWT with signer and verifies the RS256 signature
// against the given RSA public key. Used by PEM variant tests.
func assertValidRSAJWT(t *testing.T, key *rsa.PrivateKey, signer *ClientAssertionSigner, alg string) {
	t.Helper()
	jwtStr, err := signer.Sign("https://example.com/token", "pem-client")
	require.NoError(t, err)

	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3)

	hdr := decodeJSONPart(t, parts[0])
	assert.Equal(t, alg, hdr["alg"])

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	sigInput := parts[0] + "." + parts[1]
	digest := sha256SumBytes([]byte(sigInput))
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, sigBytes))
}

