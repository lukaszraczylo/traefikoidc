package traefikoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

// isSupportedClientAssertionAlg reports whether alg is a recognized JWS
// algorithm for private_key_jwt (RFC 7523 §2.2).
func isSupportedClientAssertionAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512":
		return true
	}
	return false
}

// ClientAssertionSigner builds and signs client_assertion JWTs (RFC 7523 §2.2).
type ClientAssertionSigner struct {
	key crypto.PrivateKey
	alg string
	kid string
	// rand is the entropy source for jti generation and PSS/ECDSA signing.
	// Defaults to crypto/rand.Reader when nil.
	rand io.Reader
	// now returns the current time. Defaults to time.Now when nil.
	now func() time.Time
}

// NewClientAssertionSigner parses pemBytes as a private key, validates that
// alg is consistent with the key type, and returns a ready-to-use signer.
// kid is placed verbatim in the JWS header.
//
// PEM block types understood:
//   - "PRIVATE KEY"     → PKCS#8 (tried first for all types)
//   - "RSA PRIVATE KEY" → PKCS#1
//   - "EC PRIVATE KEY"  → SEC1
func NewClientAssertionSigner(pemBytes []byte, alg, kid string) (*ClientAssertionSigner, error) {
	if !isSupportedClientAssertionAlg(alg) {
		return nil, fmt.Errorf("unsupported client assertion alg %q", alg)
	}
	if kid == "" {
		return nil, fmt.Errorf("kid must not be empty")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key material")
	}

	var key crypto.PrivateKey
	var parseErr error

	switch block.Type {
	case "PRIVATE KEY":
		key, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, parseErr = x509.ParseECPrivateKey(block.Bytes)
	default:
		// Best-effort fallback for unknown block types.
		key, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse private key (block type %q): %w", block.Type, parseErr)
	}

	if err := validateAlgKeyMatch(alg, key); err != nil {
		return nil, err
	}

	return &ClientAssertionSigner{key: key, alg: alg, kid: kid}, nil
}

// validateAlgKeyMatch returns an error when alg implies a key type that does
// not match the actual key.
func validateAlgKeyMatch(alg string, key crypto.PrivateKey) error {
	switch alg[0] {
	case 'R', 'P': // RS* or PS*
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("alg %q requires an RSA key, got %T", alg, key)
		}
	case 'E': // ES*
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("alg %q requires an EC key, got %T", alg, key)
		}
		// ES* maps 1:1 to a NIST curve (ES256→P-256, ES384→P-384,
		// ES512→P-521). A key on the wrong curve would otherwise pass this
		// check yet always produce a signature the IdP rejects.
		if want := ecdsaAlgorithmCurve(alg); want != nil && ecKey.Curve != want {
			return fmt.Errorf("alg %q requires a key on curve %s, got %s", alg, want.Params().Name, ecKey.Curve.Params().Name)
		}
	}
	return nil
}

// ecdsaAlgorithmCurve returns the NIST curve required by an ES* algorithm, or
// nil for any non-ES algorithm.
func ecdsaAlgorithmCurve(alg string) elliptic.Curve {
	switch alg {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	}
	return nil
}

// Sign constructs and returns a signed client_assertion JWT.
// audience is typically the token endpoint URL (RFC 7523 §3).
// clientID is used as both iss and sub per RFC 7523 §2.2.
func (s *ClientAssertionSigner) Sign(audience, clientID string) (string, error) {
	rander := s.rand
	if rander == nil {
		rander = rand.Reader
	}
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}

	now := nowFn()

	// 16 random bytes as lowercase hex for jti uniqueness.
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(rander, jtiBytes); err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	header := map[string]string{
		"alg": s.alg,
		"typ": "JWT",
		"kid": s.kid,
	}
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}

	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := hdrB64 + "." + claimsB64

	sig, err := s.sign(rander, []byte(signingInput))
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// sign computes raw signature bytes for signingInput per s.alg.
// validateAlgKeyMatch in NewClientAssertionSigner guarantees the key type
// matches s.alg, but the comma-ok asserts here keep errcheck happy and
// surface internal misuse loudly instead of via panic.
func (s *ClientAssertionSigner) sign(rander io.Reader, input []byte) ([]byte, error) {
	switch s.alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		rsaKey, ok := s.key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("internal: alg %q requires *rsa.PrivateKey, got %T", s.alg, s.key)
		}
		hash := rsaHashForAlg(s.alg)
		digest := hashSum(hash, input)
		if s.alg[0] == 'R' {
			return signRSAPKCS1v15(rander, rsaKey, hash, digest)
		}
		return signRSAPSS(rander, rsaKey, hash, digest)
	case "ES256", "ES384", "ES512":
		ecKey, ok := s.key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("internal: alg %q requires *ecdsa.PrivateKey, got %T", s.alg, s.key)
		}
		hash := ecHashForAlg(s.alg)
		digest := hashSum(hash, input)
		return signECDSA(rander, ecKey, digest)
	}
	return nil, fmt.Errorf("unhandled alg %q", s.alg)
}

func rsaHashForAlg(alg string) crypto.Hash {
	switch alg {
	case "RS256", "PS256":
		return crypto.SHA256
	case "RS384", "PS384":
		return crypto.SHA384
	case "RS512", "PS512":
		return crypto.SHA512
	}
	return 0
}

func ecHashForAlg(alg string) crypto.Hash {
	switch alg {
	case "ES256":
		return crypto.SHA256
	case "ES384":
		return crypto.SHA384
	case "ES512":
		return crypto.SHA512
	}
	return 0
}

func hashSum(h crypto.Hash, input []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(input)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(input)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(input)
		return sum[:]
	}
	return nil
}

func signRSAPKCS1v15(rander io.Reader, key *rsa.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	sig, err := rsa.SignPKCS1v15(rander, key, hash, digest)
	if err != nil {
		return nil, fmt.Errorf("RSA PKCS1v15 signing failed: %w", err)
	}
	return sig, nil
}

func signRSAPSS(rander io.Reader, key *rsa.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
	sig, err := rsa.SignPSS(rander, key, hash, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("RSA PSS signing failed: %w", err)
	}
	return sig, nil
}

// signECDSA produces the JWS raw r||s signature (RFC 7515 App. A.3).
// Each scalar is zero-padded to (curve.BitSize+7)/8 bytes.
func signECDSA(rander io.Reader, key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(rander, key, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	padBigInt(sig[0:byteLen], r)
	padBigInt(sig[byteLen:], ss)
	return sig, nil
}

// padBigInt writes n as a fixed-width big-endian integer into buf.
func padBigInt(buf []byte, n *big.Int) {
	b := n.Bytes()
	copy(buf[len(buf)-len(b):], b)
}

// buildClientAssertionSignerFromConfig loads key material and constructs a
// ClientAssertionSigner. Called from NewWithContext when
// ClientAuthMethod == "private_key_jwt".
func buildClientAssertionSignerFromConfig(config *Config) (*ClientAssertionSigner, error) {
	var pemBytes []byte

	if config.ClientAssertionPrivateKey != "" {
		pemBytes = []byte(config.ClientAssertionPrivateKey)
	} else {
		data, err := os.ReadFile(config.ClientAssertionKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read clientAssertionKeyPath %q: %w", config.ClientAssertionKeyPath, err)
		}
		pemBytes = data
	}

	alg := config.ClientAssertionAlg
	if alg == "" {
		alg = "RS256"
	}

	return NewClientAssertionSigner(pemBytes, alg, config.ClientAssertionKeyID)
}



