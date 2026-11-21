package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
)

// incompressibleToken returns a base64 blob too large to fit a single
// cookie after compression, so Set*Token takes the chunked path. Random
// bytes are (nearly) incompressible, unlike repeated chars.
func incompressibleToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawStdEncoding.EncodeToString(buf)
}
