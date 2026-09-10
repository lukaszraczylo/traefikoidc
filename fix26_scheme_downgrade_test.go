package traefikoidc

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

// fix26CapturingLogger builds a *Logger whose Errorf output lands in buf
// while Info/Debug are discarded, so a test can assert on exactly what
// reaches the error stream without touching the process-wide os.Stderr.
func fix26CapturingLogger(buf *bytes.Buffer) *Logger {
	return &Logger{
		logError: log.New(buf, "", 0),
		logInfo:  log.New(io.Discard, "", 0),
		logDebug: log.New(io.Discard, "", 0),
	}
}

// TestUpdateMetadataEndpoints_HTTPTokenEndpointUnderHTTPSProviderFailsLoudly
// pins FIX-26. validateDiscoveredEndpoint already drops (R146) a discovered
// http endpoint when providerURL is https, but updateMetadataEndpoints'
// sanitize closure only logged one generic "Ignoring discovered ..." line —
// identical in shape to every other validation rejection (SSRF block,
// malformed URL, path traversal, ...), with nothing that named this specific
// condition, its cause, or the fact that there is no config override. An
// operator upgrading with an IdP that advertises http endpoints over an
// https-served discovery document got a broken login with no distinguishing
// signal. The fix adds one additional, distinctly-tagged log line so the
// drop is unmistakable in logs.
func TestUpdateMetadataEndpoints_HTTPTokenEndpointUnderHTTPSProviderFailsLoudly(t *testing.T) {
	var buf bytes.Buffer
	tObj := &TraefikOidc{
		logger:      fix26CapturingLogger(&buf),
		providerURL: "https://provider.example.com",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{
		TokenURL: "http://provider.example.com/token",
	})

	if tObj.tokenURL != "" {
		t.Fatalf("an http token endpoint under an https provider must still be dropped, got %q", tObj.tokenURL)
	}

	logged := buf.String()
	if !strings.Contains(logged, "SECURITY:") {
		t.Fatalf("dropping an endpoint for the https-pin reason must log a SECURITY-tagged line, got:\n%s", logged)
	}
	if !strings.Contains(logged, "token") {
		t.Fatalf("the SECURITY line must name the dropped endpoint (token), got:\n%s", logged)
	}
	if !strings.Contains(logged, "http://provider.example.com/token") {
		t.Fatalf("the SECURITY line must name the dropped URL, got:\n%s", logged)
	}
	if !strings.Contains(logged, "no override") {
		t.Fatalf("the SECURITY line must state that this check has no override, got:\n%s", logged)
	}
}

// TestUpdateMetadataEndpoints_AllHTTPSCriticalEndpointsNoSecurityLog is the
// negative case: well-formed https endpoints (jwks_uri, authorization,
// token) must not trip the new SECURITY line.
func TestUpdateMetadataEndpoints_AllHTTPSCriticalEndpointsNoSecurityLog(t *testing.T) {
	var buf bytes.Buffer
	tObj := &TraefikOidc{
		logger:      fix26CapturingLogger(&buf),
		providerURL: "https://provider.example.com",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{
		JWKSURL:  "https://provider.example.com/jwks",
		AuthURL:  "https://provider.example.com/auth",
		TokenURL: "https://provider.example.com/token",
	})

	if tObj.tokenURL != "https://provider.example.com/token" {
		t.Fatalf("an https token endpoint must be accepted, got %q", tObj.tokenURL)
	}
	if strings.Contains(buf.String(), "SECURITY:") {
		t.Fatalf("accepted https endpoints must not log a SECURITY line, got:\n%s", buf.String())
	}
}

// TestUpdateMetadataEndpoints_HTTPJWKSAndAuthEndpointsFailLoudly extends the
// pin to the other two endpoints login cannot function without: jwks_uri
// (signature verification) and authorization (the redirect target). Each
// must independently trigger its own named SECURITY line.
func TestUpdateMetadataEndpoints_HTTPJWKSAndAuthEndpointsFailLoudly(t *testing.T) {
	for _, tc := range []struct {
		field    string
		endpoint string
	}{
		{field: "jwks_uri", endpoint: "http://provider.example.com/jwks"},
		{field: "authorization", endpoint: "http://provider.example.com/auth"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			var buf bytes.Buffer
			tObj := &TraefikOidc{
				logger:      fix26CapturingLogger(&buf),
				providerURL: "https://provider.example.com",
			}
			md := &ProviderMetadata{}
			switch tc.field {
			case "jwks_uri":
				md.JWKSURL = tc.endpoint
			case "authorization":
				md.AuthURL = tc.endpoint
			}
			tObj.updateMetadataEndpoints(md)

			logged := buf.String()
			if !strings.Contains(logged, "SECURITY:") {
				t.Fatalf("%s: dropping the endpoint must log a SECURITY-tagged line, got:\n%s", tc.field, logged)
			}
			if !strings.Contains(logged, tc.field) {
				t.Fatalf("%s: the SECURITY line must name the endpoint, got:\n%s", tc.field, logged)
			}
		})
	}
}
