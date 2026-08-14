package traefikoidc

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
)

// TestCheckForMemoryIssues_NoSpuriousLeakOnZeroHeap regresses the heap-growth
// check dividing by a zero previous HeapAlloc, which produced +Inf growth
// and a spurious "Potential memory leak" INFO alert on the first
// measurement after a fresh start (R103).
func TestCheckForMemoryIssues_NoSpuriousLeakOnZeroHeap(t *testing.T) {
	var buf bytes.Buffer
	mm := &TaskMemoryMonitor{logger: NewLogger("")}
	mm.logger.logInfo = log.New(&buf, "", 0)
	mm.statsHistory = []TaskMemoryStats{
		{HeapAlloc: 0, NumGC: 0},
		{HeapAlloc: 0, NumGC: 0},
	}
	mm.checkForMemoryIssues(TaskMemoryStats{HeapAlloc: 1024, NumGC: 0})
	if got := buf.String(); strings.Contains(got, "Potential memory leak") {
		t.Fatalf("spurious memory-leak log with previous HeapAlloc=0: %q", got)
	}
}

// TestHeaderTemplate_EmbeddedNoValuePreserved regresses the header-template
// strip of "<no value>" doing a blanket strings.ReplaceAll over the whole
// rendered output, which corrupted a legitimate claim value containing the
// substring. The strip now matches "<no value>" only as a whole token, so
// a value where it is embedded within a larger token survives verbatim;
// genuine missing-key renders are still removed (existing
// TestHeaderTemplate_MissingClaimNoNoValue keeps passing).
func TestHeaderTemplate_EmbeddedNoValuePreserved(t *testing.T) {
	oidc := &TraefikOidc{
		next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:         NewLogger("error"),
		groupClaimName: "groups",
		roleClaimName:  "roles",
		minimalHeaders: true,
		headerTemplates: map[string]*template.Template{
			"X-Note": mustTemplate("{{.Claims.note}}"),
			"X-Ip":   mustTemplate("{{.RemoteAddr}}"),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	p := &principal{
		Identifier: "user",
		Claims: map[string]interface{}{
			"sub":  "subject",
			"note": "branch<no value>submit", // embedded, not a whole token
		},
	}
	oidc.forwardAuthorized(rw, req, p)

	if got := req.Header.Get("X-Note"); got != "branch<no value>submit" {
		t.Fatalf("embedded '<no value>' in a claim value was corrupted; got %q", got)
	}
}
