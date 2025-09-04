package traefikoidc

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SecurityEventType categorizes different types of security events
// that can occur during OIDC authentication and authorization flows.
type SecurityEventType string

// Security event types for monitoring and alerting
const (
	// AuthFailure indicates a failed authentication attempt
	AuthFailure SecurityEventType = "authentication_failure"
	// TokenValidFailure indicates JWT token validation failed
	TokenValidFailure SecurityEventType = "token_validation_failure"
	// RateLimitHit indicates rate limiting was triggered
	RateLimitHit SecurityEventType = "rate_limit_hit"
	// SuspiciousActivity indicates potentially malicious behavior
	SuspiciousActivity SecurityEventType = "suspicious_activity"
)

// DefaultSeverity returns the default severity level for each security event type.
// Severity levels are: low, medium, high.
func (t SecurityEventType) DefaultSeverity() string {
	switch t {
	case AuthFailure:
		return "medium"
	case TokenValidFailure:
		return "medium"
	case RateLimitHit:
		return "low"
	case SuspiciousActivity:
		return "high"
	default:
		return "medium"
	}
}

// IPFailureType returns a string identifier for categorizing failures
// by IP address for rate limiting and blocking decisions.
func (t SecurityEventType) IPFailureType() string {
	switch t {
	case AuthFailure:
		return "auth_failure"
	case TokenValidFailure:
		return "token_failure"
	case SuspiciousActivity:
		return "suspicious"
	default:
		return "general"
	}
}

// SecurityEvent represents a security-related event with comprehensive context.
// Contains timing information, IP address, user agent, request details,
// and custom event-specific data for security analysis and alerting.
type SecurityEvent struct {
	// Timestamp when the event occurred
	Timestamp time.Time `json:"timestamp"`
	// Details contains event-specific additional information
	Details map[string]interface{} `json:"details,omitempty"`
	// Type categorizes the event (auth_failure, token_failure, etc.)
	Type string `json:"type"`
	// Severity indicates event importance (low, medium, high)
	Severity string `json:"severity"`
	// ClientIP is the source IP address of the request
	ClientIP string `json:"client_ip"`
	// UserAgent is the User-Agent header from the request
	UserAgent string `json:"user_agent"`
	// RequestPath is the requested URL path
	RequestPath string `json:"request_path"`
	// Message provides human-readable description of the event
	Message string `json:"message"`
}

// SecurityMonitor provides comprehensive security monitoring for the OIDC middleware.
// It tracks failures by IP address, detects suspicious patterns, enforces
// rate limits, and can trigger custom security event handlers.
type SecurityMonitor struct {
	ipFailures      map[string]*IPFailureTracker
	patternDetector *SuspiciousPatternDetector
	logger          *Logger
	cleanupTask     *BackgroundTask
	eventHandlers   []SecurityEventHandler
	config          SecurityMonitorConfig
	ipMutex         sync.RWMutex
}

// IPFailureTracker maintains failure statistics and blocking state for an IP address.
// Used for implementing progressive penalties and automatic IP blocking based on
// failure patterns, with support for different failure types for
// rate limiting and IP blocking decisions.
type IPFailureTracker struct {
	// LastFailure timestamp of the most recent failure
	LastFailure time.Time
	// FirstFailure timestamp of the first failure in current window
	FirstFailure time.Time
	// BlockedUntil indicates when the IP block expires
	BlockedUntil time.Time
	// FailureTypes tracks counts by failure type
	FailureTypes map[string]int64
	// FailureCount total number of failures
	FailureCount int64
	// mutex protects concurrent access to tracker data
	mutex sync.RWMutex
	// IsBlocked indicates if this IP is currently blocked
	IsBlocked bool
}

// SuspiciousPatternDetector identifies attack patterns that may indicate coordinated threats.
// Analyzes events across multiple time windows to detect rapid failures, distributed attacks,
// and persistent attack patterns that individual IP monitoring might miss.
type SuspiciousPatternDetector struct {
	// recentEvents stores recent security events for analysis
	recentEvents []SecurityEvent
	// shortWindow defines time frame for rapid failure detection
	shortWindow time.Duration
	// mediumWindow defines time frame for distributed attack detection
	mediumWindow time.Duration
	// longWindow defines time frame for persistent attack detection
	longWindow time.Duration
	// rapidFailureThreshold triggers rapid failure alerts
	rapidFailureThreshold int
	// distributedAttackThreshold triggers distributed attack alerts
	distributedAttackThreshold int
	// persistentAttackThreshold triggers persistent attack alerts
	persistentAttackThreshold int
	// eventsMutex protects concurrent access to events
	eventsMutex sync.RWMutex
}

// SecurityEventHandler defines the interface for processing security events.
// Implementations can log events, send alerts, update external systems,
// or trigger automated response actions.
type SecurityEventHandler interface {
	// HandleSecurityEvent processes a security event
	HandleSecurityEvent(event SecurityEvent)
}

// SecurityMonitorConfig contains configuration parameters for the security monitor.
// Controls thresholds, time windows, and behavior for security monitoring.
type SecurityMonitorConfig struct {
	// MaxFailuresPerIP sets the failure threshold before blocking
	MaxFailuresPerIP int `json:"max_failures_per_ip"`
	// FailureWindowMinutes defines the time window for counting failures
	FailureWindowMinutes int `json:"failure_window_minutes"`
	// BlockDurationMinutes sets how long to block an IP
	BlockDurationMinutes int `json:"block_duration_minutes"`
	// RapidFailureThreshold triggers rapid failure detection
	RapidFailureThreshold int `json:"rapid_failure_threshold"`
	// CleanupIntervalMinutes sets cleanup frequency for old data
	CleanupIntervalMinutes int  `json:"cleanup_interval_minutes"`
	RetentionHours         int  `json:"retention_hours"`
	EnablePatternDetection bool `json:"enable_pattern_detection"`
	EnableDetailedLogging  bool `json:"enable_detailed_logging"`
	LogSuspiciousOnly      bool `json:"log_suspicious_only"`
}

// DefaultSecurityMonitorConfig returns a default configuration
func DefaultSecurityMonitorConfig() SecurityMonitorConfig {
	return SecurityMonitorConfig{
		MaxFailuresPerIP:       10,
		FailureWindowMinutes:   15,
		BlockDurationMinutes:   60,
		EnablePatternDetection: true,
		RapidFailureThreshold:  5,
		EnableDetailedLogging:  true,
		LogSuspiciousOnly:      false,
		CleanupIntervalMinutes: 30,
		RetentionHours:         24,
	}
}

// NewSecurityMonitor creates a new security monitor instance
func NewSecurityMonitor(config SecurityMonitorConfig, logger *Logger) *SecurityMonitor {
	sm := &SecurityMonitor{
		ipFailures:      make(map[string]*IPFailureTracker),
		eventHandlers:   make([]SecurityEventHandler, 0),
		config:          config,
		logger:          logger,
		patternDetector: NewSuspiciousPatternDetector(),
	}

	sm.startCleanupRoutine()

	return sm
}

// NewSuspiciousPatternDetector creates a new pattern detector
func NewSuspiciousPatternDetector() *SuspiciousPatternDetector {
	return &SuspiciousPatternDetector{
		shortWindow:                1 * time.Minute,
		mediumWindow:               5 * time.Minute,
		longWindow:                 15 * time.Minute,
		rapidFailureThreshold:      5,
		distributedAttackThreshold: 20,
		persistentAttackThreshold:  50,
		recentEvents:               make([]SecurityEvent, 0),
	}
}

// RecordSecurityEvent is a generic method to record any type of security event
func (sm *SecurityMonitor) RecordSecurityEvent(
	eventType SecurityEventType,
	clientIP, userAgent, requestPath string,
	message string,
	details map[string]interface{},
	trackIPFailure bool) {

	event := SecurityEvent{
		Type:        string(eventType),
		Severity:    eventType.DefaultSeverity(),
		Timestamp:   time.Now(),
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		RequestPath: requestPath,
		Message:     message,
		Details:     details,
	}

	if trackIPFailure {
		sm.recordIPFailure(clientIP, eventType.IPFailureType())
	}

	sm.processSecurityEvent(event)
}

// RecordAuthenticationFailure records an authentication failure event
func (sm *SecurityMonitor) RecordAuthenticationFailure(clientIP, userAgent, requestPath, reason string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["reason"] = reason

	sm.RecordSecurityEvent(
		AuthFailure,
		clientIP,
		userAgent,
		requestPath,
		fmt.Sprintf("Authentication failed: %s", reason),
		details,
		true,
	)
}

// RecordTokenValidationFailure records a token validation failure
func (sm *SecurityMonitor) RecordTokenValidationFailure(clientIP, userAgent, requestPath, reason string, tokenPrefix string) {
	details := map[string]interface{}{
		"reason": reason,
	}
	if tokenPrefix != "" {
		details["token_prefix"] = tokenPrefix
	}

	sm.RecordSecurityEvent(
		TokenValidFailure,
		clientIP,
		userAgent,
		requestPath,
		fmt.Sprintf("Token validation failed: %s", reason),
		details,
		true,
	)
}

// RecordRateLimitHit records when rate limiting is triggered
func (sm *SecurityMonitor) RecordRateLimitHit(clientIP, userAgent, requestPath string) {
	details := map[string]interface{}{
		"limit_type": "token_verification",
	}

	sm.RecordSecurityEvent(
		RateLimitHit,
		clientIP,
		userAgent,
		requestPath,
		"Rate limit exceeded",
		details,
		true,
	)
}

// RecordSuspiciousActivity records suspicious activity that doesn't fit other categories
func (sm *SecurityMonitor) RecordSuspiciousActivity(clientIP, userAgent, requestPath, activityType, description string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["activity_type"] = activityType

	sm.RecordSecurityEvent(
		SuspiciousActivity,
		clientIP,
		userAgent,
		requestPath,
		fmt.Sprintf("Suspicious activity detected: %s - %s", activityType, description),
		details,
		true,
	)
}

// recordIPFailure tracks failures for a specific IP address
func (sm *SecurityMonitor) recordIPFailure(clientIP, failureType string) {
	sm.ipMutex.Lock()
	defer sm.ipMutex.Unlock()

	tracker, exists := sm.ipFailures[clientIP]
	if !exists {
		tracker = &IPFailureTracker{
			FailureTypes: make(map[string]int64),
			FirstFailure: time.Now(),
		}
		sm.ipFailures[clientIP] = tracker
	}

	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	tracker.FailureCount++
	tracker.LastFailure = time.Now()
	tracker.FailureTypes[failureType]++

	windowStart := time.Now().Add(-time.Duration(sm.config.FailureWindowMinutes) * time.Minute)
	if tracker.FirstFailure.After(windowStart) && tracker.FailureCount >= int64(sm.config.MaxFailuresPerIP) {
		if !tracker.IsBlocked {
			tracker.IsBlocked = true
			tracker.BlockedUntil = time.Now().Add(time.Duration(sm.config.BlockDurationMinutes) * time.Minute)

			sm.logger.Errorf("IP %s blocked due to %d failures (types: %v)", clientIP, tracker.FailureCount, tracker.FailureTypes)

			blockEvent := SecurityEvent{
				Type:      "ip_blocked",
				Severity:  "high",
				Timestamp: time.Now(),
				ClientIP:  clientIP,
				Message:   fmt.Sprintf("IP blocked due to %d failures in %d minutes", tracker.FailureCount, sm.config.FailureWindowMinutes),
				Details: map[string]interface{}{
					"failure_count": tracker.FailureCount,
					"failure_types": tracker.FailureTypes,
					"blocked_until": tracker.BlockedUntil,
				},
			}
			sm.processSecurityEvent(blockEvent)
		}
	}
}

// IsIPBlocked checks if an IP address is currently blocked
func (sm *SecurityMonitor) IsIPBlocked(clientIP string) bool {
	sm.ipMutex.RLock()
	defer sm.ipMutex.RUnlock()

	tracker, exists := sm.ipFailures[clientIP]
	if !exists {
		return false
	}

	tracker.mutex.RLock()
	defer tracker.mutex.RUnlock()

	if tracker.IsBlocked && time.Now().Before(tracker.BlockedUntil) {
		return true
	}

	if tracker.IsBlocked && time.Now().After(tracker.BlockedUntil) {
		tracker.IsBlocked = false
		sm.logger.Infof("IP %s automatically unblocked", clientIP)
	}

	return false
}

// processSecurityEvent processes a security event through all handlers and pattern detection
func (sm *SecurityMonitor) processSecurityEvent(event SecurityEvent) {
	if sm.config.EnablePatternDetection {
		sm.patternDetector.AddEvent(event)

		if patterns := sm.patternDetector.DetectSuspiciousPatterns(); len(patterns) > 0 {
			if len(patterns) == 1 {
				sm.logger.Errorf("Suspicious pattern detected: %s", patterns[0])
			} else {
				sm.logger.Errorf("Multiple suspicious patterns detected: %v", patterns)
			}

			for _, pattern := range patterns {
				patternEvent := SecurityEvent{
					Type:      "suspicious_pattern",
					Severity:  "high",
					Timestamp: time.Now(),
					Message:   fmt.Sprintf("Suspicious pattern detected: %s", pattern),
					Details: map[string]interface{}{
						"pattern_type":  pattern,
						"trigger_event": event,
					},
				}
				sm.handleSecurityEvent(patternEvent)
			}
		}
	}

	sm.handleSecurityEvent(event)
}

// handleSecurityEvent sends the event to all registered handlers
func (sm *SecurityMonitor) handleSecurityEvent(event SecurityEvent) {
	if sm.config.EnableDetailedLogging && (!sm.config.LogSuspiciousOnly || event.Severity == "high") {
		sm.logger.Infof("Security Event [%s/%s]: %s (IP: %s, Path: %s)",
			event.Type, event.Severity, event.Message, event.ClientIP, event.RequestPath)
	}

	for _, handler := range sm.eventHandlers {
		go handler.HandleSecurityEvent(event)
	}
}

// AddEventHandler adds a security event handler
func (sm *SecurityMonitor) AddEventHandler(handler SecurityEventHandler) {
	sm.eventHandlers = append(sm.eventHandlers, handler)
}

// This is kept for API compatibility but doesn't collect actual metrics
func (sm *SecurityMonitor) GetSecurityMetrics() map[string]interface{} {
	return map[string]interface{}{
		"tracked_ips": 0,
	}
}

// AddEvent adds an event to the pattern detector
func (spd *SuspiciousPatternDetector) AddEvent(event SecurityEvent) {
	spd.eventsMutex.Lock()
	defer spd.eventsMutex.Unlock()

	spd.recentEvents = append(spd.recentEvents, event)

	cutoff := time.Now().Add(-spd.longWindow)
	var filteredEvents []SecurityEvent
	for _, e := range spd.recentEvents {
		if e.Timestamp.After(cutoff) {
			filteredEvents = append(filteredEvents, e)
		}
	}
	spd.recentEvents = filteredEvents
}

// DetectSuspiciousPatterns analyzes recent events for suspicious patterns
func (spd *SuspiciousPatternDetector) DetectSuspiciousPatterns() []string {
	spd.eventsMutex.RLock()
	defer spd.eventsMutex.RUnlock()

	var patterns []string
	now := time.Now()

	ipCounts := make(map[string]int)
	shortWindowStart := now.Add(-spd.shortWindow)

	for _, event := range spd.recentEvents {
		if event.Timestamp.After(shortWindowStart) &&
			(event.Type == "authentication_failure" || event.Type == "token_validation_failure") {
			ipCounts[event.ClientIP]++
		}
	}

	for ip, count := range ipCounts {
		if count >= spd.rapidFailureThreshold {
			patterns = append(patterns, fmt.Sprintf("rapid_failures_from_ip_%s", ip))
		}
	}

	mediumWindowStart := now.Add(-spd.mediumWindow)
	uniqueFailingIPs := make(map[string]bool)

	for _, event := range spd.recentEvents {
		if event.Timestamp.After(mediumWindowStart) &&
			(event.Type == "authentication_failure" || event.Type == "token_validation_failure") {
			uniqueFailingIPs[event.ClientIP] = true
		}
	}

	if len(uniqueFailingIPs) >= spd.distributedAttackThreshold {
		patterns = append(patterns, "distributed_attack_pattern")
	}

	longWindowStart := now.Add(-spd.longWindow)
	persistentFailures := 0

	for _, event := range spd.recentEvents {
		if event.Timestamp.After(longWindowStart) &&
			(event.Type == "authentication_failure" || event.Type == "token_validation_failure") {
			persistentFailures++
		}
	}

	if persistentFailures >= spd.persistentAttackThreshold {
		patterns = append(patterns, "persistent_attack_pattern")
	}

	return patterns
}

// startCleanupRoutine starts the background cleanup routine
func (sm *SecurityMonitor) startCleanupRoutine() {
	sm.cleanupTask = NewBackgroundTask(
		"security-monitor-cleanup",
		time.Duration(sm.config.CleanupIntervalMinutes)*time.Minute,
		sm.cleanup,
		sm.logger)
	sm.cleanupTask.Start()
}

// StopCleanupRoutine stops the background cleanup routine
func (sm *SecurityMonitor) StopCleanupRoutine() {
	if sm.cleanupTask != nil {
		sm.cleanupTask.Stop()
		sm.cleanupTask = nil
	}
}

// cleanup removes old tracking data
func (sm *SecurityMonitor) cleanup() {
	sm.ipMutex.Lock()
	defer sm.ipMutex.Unlock()

	cutoff := time.Now().Add(-time.Duration(sm.config.RetentionHours) * time.Hour)

	for ip, tracker := range sm.ipFailures {
		tracker.mutex.RLock()
		shouldRemove := tracker.LastFailure.Before(cutoff) && !tracker.IsBlocked
		tracker.mutex.RUnlock()

		if shouldRemove {
			delete(sm.ipFailures, ip)
		}
	}

	sm.logger.Debugf("Security monitor cleanup completed, tracking %d IPs", len(sm.ipFailures))
}

// ExtractClientIP extracts the client IP from the request, considering proxy headers
func ExtractClientIP(r *http.Request) string {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LoggingSecurityEventHandler logs security events to the standard logger
type LoggingSecurityEventHandler struct {
	logger *Logger
}

// NewLoggingSecurityEventHandler creates a new logging event handler
func NewLoggingSecurityEventHandler(logger *Logger) *LoggingSecurityEventHandler {
	return &LoggingSecurityEventHandler{logger: logger}
}

// HandleSecurityEvent implements SecurityEventHandler
func (h *LoggingSecurityEventHandler) HandleSecurityEvent(event SecurityEvent) {
	switch event.Severity {
	case "high":
		h.logger.Errorf("SECURITY [%s]: %s (IP: %s)", event.Type, event.Message, event.ClientIP)
	case "medium":
		h.logger.Errorf("SECURITY [%s]: %s (IP: %s)", event.Type, event.Message, event.ClientIP)
	case "low":
		h.logger.Infof("SECURITY [%s]: %s (IP: %s)", event.Type, event.Message, event.ClientIP)
	default:
		h.logger.Debugf("SECURITY [%s]: %s (IP: %s)", event.Type, event.Message, event.ClientIP)
	}
}
