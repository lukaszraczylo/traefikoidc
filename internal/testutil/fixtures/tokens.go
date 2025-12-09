package fixtures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

// TokenFixture provides JWT token generation for tests
type TokenFixture struct {
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
	ECPrivateKey  *ecdsa.PrivateKey
	ECPublicKey   *ecdsa.PublicKey
	KeyID         string
	Issuer        string
	Audience      string
	ClockSkew     time.Duration
}

// NewTokenFixture creates a new token fixture with generated keys
func NewTokenFixture() (*TokenFixture, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &TokenFixture{
		RSAPrivateKey: rsaKey,
		RSAPublicKey:  &rsaKey.PublicKey,
		ECPrivateKey:  ecKey,
		ECPublicKey:   &ecKey.PublicKey,
		KeyID:         "test-key-id",
		Issuer:        "https://test-issuer.com",
		Audience:      "test-client-id",
		ClockSkew:     2 * time.Minute,
	}, nil
}

// DefaultClaims returns standard JWT claims
func (f *TokenFixture) DefaultClaims() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss":   f.Issuer,
		"aud":   f.Audience,
		"sub":   "test-subject",
		"email": "user@example.com",
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Add(-f.ClockSkew).Unix(),
		"nbf":   now.Add(-f.ClockSkew).Unix(),
		"nonce": "test-nonce",
		"jti":   generateJTI(),
	}
}

// ValidToken creates a valid JWT token with optional claim overrides
func (f *TokenFixture) ValidToken(claimOverrides map[string]interface{}) (string, error) {
	claims := f.DefaultClaims()
	for k, v := range claimOverrides {
		claims[k] = v
	}
	return f.createJWT(claims, "RS256", f.KeyID)
}

// ExpiredToken creates an expired JWT token
func (f *TokenFixture) ExpiredToken() (string, error) {
	claims := f.DefaultClaims()
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	return f.createJWT(claims, "RS256", f.KeyID)
}

// NotYetValidToken creates a token that's not valid yet
func (f *TokenFixture) NotYetValidToken() (string, error) {
	claims := f.DefaultClaims()
	claims["nbf"] = time.Now().Add(1 * time.Hour).Unix()
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithSkew creates a token with a specific time offset
func (f *TokenFixture) TokenWithSkew(skew time.Duration) (string, error) {
	claims := f.DefaultClaims()
	claims["exp"] = time.Now().Add(skew).Unix()
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithRoles creates a token with specific roles
func (f *TokenFixture) TokenWithRoles(roles []string) (string, error) {
	claims := f.DefaultClaims()
	claims["roles"] = roles
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithGroups creates a token with specific groups
func (f *TokenFixture) TokenWithGroups(groups []string) (string, error) {
	claims := f.DefaultClaims()
	claims["groups"] = groups
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithEmail creates a token with a specific email
func (f *TokenFixture) TokenWithEmail(email string) (string, error) {
	claims := f.DefaultClaims()
	claims["email"] = email
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithAudience creates a token with a specific audience
func (f *TokenFixture) TokenWithAudience(audience string) (string, error) {
	claims := f.DefaultClaims()
	claims["aud"] = audience
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithIssuer creates a token with a specific issuer
func (f *TokenFixture) TokenWithIssuer(issuer string) (string, error) {
	claims := f.DefaultClaims()
	claims["iss"] = issuer
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenMissingClaim creates a token missing specified claims
func (f *TokenFixture) TokenMissingClaim(missingClaims ...string) (string, error) {
	claims := f.DefaultClaims()
	for _, claim := range missingClaims {
		delete(claims, claim)
	}
	return f.createJWT(claims, "RS256", f.KeyID)
}

// TokenWithCustomClaims creates a token with custom claims
func (f *TokenFixture) TokenWithCustomClaims(customClaims map[string]interface{}) (string, error) {
	claims := f.DefaultClaims()
	for k, v := range customClaims {
		claims[k] = v
	}
	return f.createJWT(claims, "RS256", f.KeyID)
}

// MalformedToken returns an invalid JWT string
func (f *TokenFixture) MalformedToken() string {
	return "not.a.valid.jwt"
}

// EmptyToken returns an empty string
func (f *TokenFixture) EmptyToken() string {
	return ""
}

// TokenWithWrongSignature creates a token signed with a different key
func (f *TokenFixture) TokenWithWrongSignature() (string, error) {
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	claims := f.DefaultClaims()
	return createJWTWithKey(claims, "RS256", f.KeyID, wrongKey)
}

// TokenWithWrongAlgorithm creates a token with mismatched algorithm
func (f *TokenFixture) TokenWithWrongAlgorithm() (string, error) {
	claims := f.DefaultClaims()
	// Create token claiming RS256 but we'll return it as-is
	// This simulates algorithm confusion attacks
	return f.createJWT(claims, "none", f.KeyID)
}

// ECToken creates a token signed with EC key
func (f *TokenFixture) ECToken() (string, error) {
	claims := f.DefaultClaims()
	return f.createECJWT(claims, "ES256", f.KeyID)
}

// GetJWKS returns a JWKS containing the test public key
func (f *TokenFixture) GetJWKS() map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": f.KeyID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(f.RSAPublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(f.RSAPublicKey.E)))),
			},
		},
	}
}

// GetJWKSBytes returns JWKS as JSON bytes
func (f *TokenFixture) GetJWKSBytes() ([]byte, error) {
	return json.Marshal(f.GetJWKS())
}

// createJWT creates a JWT with the fixture's RSA key
func (f *TokenFixture) createJWT(claims map[string]interface{}, alg, kid string) (string, error) {
	return createJWTWithKey(claims, alg, kid, f.RSAPrivateKey)
}

// createECJWT creates a JWT with the fixture's EC key
func (f *TokenFixture) createECJWT(claims map[string]interface{}, alg, kid string) (string, error) {
	return createECJWTWithKey(claims, alg, kid, f.ECPrivateKey)
}

// Helper functions

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // #nosec G104 - test fixture, crypto strength not critical
	return base64.RawURLEncoding.EncodeToString(b)
}

func bigIntToBytes(i *big.Int) []byte {
	return i.Bytes()
}

func createJWTWithKey(claims map[string]interface{}, alg, kid string, key *rsa.PrivateKey) (string, error) {
	header := map[string]interface{}{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64

	// For "none" algorithm, return without signature
	if alg == "none" {
		return signingInput + ".", nil
	}

	// Sign with RSA-SHA256
	signature, err := signRS256([]byte(signingInput), key)
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureB64, nil
}

func createECJWTWithKey(claims map[string]interface{}, alg, kid string, key *ecdsa.PrivateKey) (string, error) {
	header := map[string]interface{}{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64

	// Sign with ECDSA-SHA256
	signature, err := signES256([]byte(signingInput), key)
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureB64, nil
}

func signRS256(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	h := hashSHA256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h)
}

func signES256(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	h := hashSHA256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h)
	if err != nil {
		return nil, err
	}

	// Encode r and s as fixed-size byte arrays
	curveBits := key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	signature := make([]byte, 2*keyBytes)
	copy(signature[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(signature[2*keyBytes-len(sBytes):], sBytes)

	return signature, nil
}

func hashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
