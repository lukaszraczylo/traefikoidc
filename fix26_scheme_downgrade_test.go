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
// http endpoint when providerURL is https, and the pre-existing "Ignoring
// discovered ..." ERROR line already names the endpoint, the URL, and the
// scheme-downgrade reason (it wraps ErrDiscoveredEndpointSchemeDowngrade).
// What was missing was a way to tell that rejection apart, at a glance, from
// every other validation rejection (SSRF block, malformed URL, path
// traversal, ...) for the three endpoints login cannot function without. The
// fix adds one additional, distinctly-tagged SECURITY line — naming the
// endpoint and stating there is no config override — for exactly those
// three (jwks_uri, authorization, token); the other four discovered
// endpoints (revocation, end_session, introspection, registration) keep
// only the generic line, since three of them (revocationURL,
// oidcEndSessionURL, introspectionURL) have an operator override that
// replaces them right after sanitize runs.
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

// TestUpdateMetadataEndpoints_NonCriticalHTTPEndpointsNoSecurityLog pins the
// documented scope of the SECURITY line: docs/CONFIGURATION.md, CHANGELOG.md
// and README.md all say it fires only for jwks_uri, authorization and token.
// end_session, revocation, introspection and registration must still be
// dropped (generic "Ignoring discovered" ERROR line only) but must never
// trip the SECURITY-tagged line — three of the four have a config override
// (revocationURL, oidcEndSessionURL, introspectionURL) that replaces the
// endpoint right after sanitize runs, so nothing actually fails for them.
func TestUpdateMetadataEndpoints_NonCriticalHTTPEndpointsNoSecurityLog(t *testing.T) {
	for _, tc := range []struct {
		field    string
		endpoint string
	}{
		{field: "end_session", endpoint: "http://provider.example.com/logout"},
		{field: "revocation", endpoint: "http://provider.example.com/revoke"},
		{field: "introspection", endpoint: "http://provider.example.com/introspect"},
		{field: "registration", endpoint: "http://provider.example.com/register"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			var buf bytes.Buffer
			tObj := &TraefikOidc{
				logger:      fix26CapturingLogger(&buf),
				providerURL: "https://provider.example.com",
			}
			md := &ProviderMetadata{}
			switch tc.field {
			case "end_session":
				md.EndSessionURL = tc.endpoint
			case "revocation":
				md.RevokeURL = tc.endpoint
			case "introspection":
				md.IntrospectionURL = tc.endpoint
			case "registration":
				md.RegistrationURL = tc.endpoint
			}
			tObj.updateMetadataEndpoints(md)

			logged := buf.String()
			if !strings.Contains(logged, "Ignoring discovered "+tc.field) {
				t.Fatalf("%s: the endpoint must still be dropped with the generic line, got:\n%s", tc.field, logged)
			}
			if strings.Contains(logged, "SECURITY:") {
				t.Fatalf("%s: only jwks_uri/authorization/token may log a SECURITY line, got:\n%s", tc.field, logged)
			}
		})
	}
}

// TestUpdateMetadataEndpoints_ConfigOverrideReplacesDroppedEndpoint pins the
// second half of the same finding: setting an operator override
// (oidcEndSessionURL here) for an endpoint that discovery drops for the
// scheme-downgrade reason means the endpoint does not stay empty — the
// override runs right after sanitize and replaces it, so a "requests needing
// this endpoint will fail" style claim would be false for these three.
func TestUpdateMetadataEndpoints_ConfigOverrideReplacesDroppedEndpoint(t *testing.T) {
	var buf bytes.Buffer
	tObj := &TraefikOidc{
		logger:              fix26CapturingLogger(&buf),
		providerURL:         "https://provider.example.com",
		configEndSessionURL: "https://provider.example.com/logout-override",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{
		EndSessionURL: "http://provider.example.com/logout",
	})

	if tObj.endSessionURL != "https://provider.example.com/logout-override" {
		t.Fatalf("configEndSessionURL must replace the dropped discovered endpoint, got %q", tObj.endSessionURL)
	}
	if strings.Contains(buf.String(), "SECURITY:") {
		t.Fatalf("end_session has a config override, so no SECURITY line applies, got:\n%s", buf.String())
	}
}
