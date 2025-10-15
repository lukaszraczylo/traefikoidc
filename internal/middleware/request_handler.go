package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RequestContext holds request processing context
type RequestContext struct {
	Writer      http.ResponseWriter
	Request     *http.Request
	RedirectURL string
	Scheme      string
	Host        string
}

// RequestProcessor handles common request processing operations
type RequestProcessor struct {
	logger Logger
}

// Logger interface for logging operations
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
}

// NewRequestProcessor creates a new request processor
func NewRequestProcessor(logger Logger) *RequestProcessor {
	return &RequestProcessor{
		logger: logger,
	}
}

// BuildRequestContext creates a request context with scheme and host detection
func (rp *RequestProcessor) BuildRequestContext(rw http.ResponseWriter, req *http.Request, redirectPath string) *RequestContext {
	scheme := rp.determineScheme(req)
	host := rp.determineHost(req)
	redirectURL := buildFullURL(scheme, host, redirectPath)

	return &RequestContext{
		Writer:      rw,
		Request:     req,
		RedirectURL: redirectURL,
		Scheme:      scheme,
		Host:        host,
	}
}

// IsHealthCheckRequest checks if request is a health check
func (rp *RequestProcessor) IsHealthCheckRequest(req *http.Request) bool {
	return strings.HasPrefix(req.URL.Path, "/health")
}

// IsEventStreamRequest checks if request expects event stream
func (rp *RequestProcessor) IsEventStreamRequest(req *http.Request) bool {
	acceptHeader := req.Header.Get("Accept")
	return strings.Contains(acceptHeader, "text/event-stream")
}

// IsAjaxRequest determines if this is an AJAX request
func (rp *RequestProcessor) IsAjaxRequest(req *http.Request) bool {
	xhr := req.Header.Get("X-Requested-With")
	contentType := req.Header.Get("Content-Type")
	accept := req.Header.Get("Accept")

	return xhr == "XMLHttpRequest" ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(accept, "application/json")
}

// WaitForInitialization waits for OIDC provider initialization with timeout
func (rp *RequestProcessor) WaitForInitialization(req *http.Request, initComplete <-chan struct{}) error {
	select {
	case <-initComplete:
		return nil
	case <-req.Context().Done():
		rp.logger.Debug("Request canceled while waiting for OIDC initialization")
		return fmt.Errorf("request canceled")
	case <-time.After(30 * time.Second):
		rp.logger.Error("Timeout waiting for OIDC initialization")
		return fmt.Errorf("timeout waiting for OIDC provider initialization")
	}
}

// determineScheme determines the URL scheme for building redirect URLs
func (rp *RequestProcessor) determineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// determineHost determines the host for building redirect URLs
func (rp *RequestProcessor) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// buildFullURL constructs a complete URL from scheme, host, and path components
func buildFullURL(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}
