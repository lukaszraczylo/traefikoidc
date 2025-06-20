package traefikoidc

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestSecurityMonitor(t *testing.T) {
	config := DefaultSecurityMonitorConfig()
	config.MaxFailuresPerIP = 3
	config.BlockDurationMinutes = 1 // 1 minute for testing
	config.CleanupIntervalMinutes = 1

	logger := NewLogger("debug")
	monitor := NewSecurityMonitor(config, logger)
	defer func() {
		// Allow cleanup goroutine to finish
		time.Sleep(150 * time.Millisecond)
	}()

	t.Run("Record authentication failure", func(t *testing.T) {
		monitor.RecordAuthenticationFailure("192.168.1.1", "test-agent", "/login", "invalid credentials", nil)

		// Should not be blocked after first failure
		if monitor.IsIPBlocked("192.168.1.1") {
			t.Error("IP should not be blocked after first failure")
		}
	})

	t.Run("IP blocked after max failures", func(t *testing.T) {
		// Record multiple failures
		for i := 0; i < config.MaxFailuresPerIP; i++ {
			monitor.RecordAuthenticationFailure("192.168.1.2", "test-agent", "/login", "invalid credentials", nil)
		}

		// Should be blocked now
		if !monitor.IsIPBlocked("192.168.1.2") {
			t.Error("IP should be blocked after max failures")
		}
	})

	t.Run("Token validation failure", func(t *testing.T) {
		// Just verify the method doesn't panic
		monitor.RecordTokenValidationFailure("192.168.1.3", "test-agent", "/api", "invalid token", "abc123")
	})

	t.Run("Rate limit hit", func(t *testing.T) {
		// Just verify the method doesn't panic
		monitor.RecordRateLimitHit("192.168.1.4", "test-agent", "/api")
	})

	t.Run("Suspicious activity", func(t *testing.T) {
		details := map[string]interface{}{"pattern": "unusual"}
		// Just verify the method doesn't panic
		monitor.RecordSuspiciousActivity("192.168.1.5", "test-agent", "/admin", "unusual pattern", "high frequency requests", details)
	})
}

func TestSuspiciousPatternDetector(t *testing.T) {
	detector := NewSuspiciousPatternDetector()

	t.Run("Add events and detect patterns", func(t *testing.T) {
		// Add multiple events from same IP
		for i := 0; i < 10; i++ {
			event := SecurityEvent{
				Type:      "authentication_failure",
				ClientIP:  "192.168.1.100",
				Timestamp: time.Now(),
			}
			detector.AddEvent(event)
		}

		patterns := detector.DetectSuspiciousPatterns()

		found := false
		for _, p := range patterns {
			if p == "rapid_failures_from_ip_192.168.1.100" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to detect rapid failure pattern")
		}
	})

	t.Run("Detect distributed attack pattern", func(t *testing.T) {
		// Add failures from many different IPs
		for i := 0; i < 25; i++ {
			event := SecurityEvent{
				Type:      "authentication_failure",
				ClientIP:  "192.168.1." + strconv.Itoa(100+i),
				Timestamp: time.Now(),
			}
			detector.AddEvent(event)
		}

		patterns := detector.DetectSuspiciousPatterns()

		found := false
		for _, p := range patterns {
			if p == "distributed_attack_pattern" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to detect distributed attack pattern")
		}
	})
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "Direct connection",
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For header",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.1"},
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "203.0.113.2"},
			expectedIP: "203.0.113.2",
		},
		{
			name:       "Multiple headers - X-Real-IP takes precedence",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			expectedIP: "203.0.113.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ip := ExtractClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestSecurityEventHandlers(t *testing.T) {
	t.Run("Logging security event handler", func(t *testing.T) {
		logger := NewLogger("debug")
		handler := NewLoggingSecurityEventHandler(logger)

		event := SecurityEvent{
			Type:      "authentication_failure",
			ClientIP:  "192.168.1.1",
			Timestamp: time.Now(),
			Message:   "Test failure",
			Severity:  "medium",
		}

		// Should not panic
		handler.HandleSecurityEvent(event)
	})

	// Metrics security event handler test removed as part of metrics cleanup
}

func TestSecurityMonitorEventHandlers(t *testing.T) {
	config := DefaultSecurityMonitorConfig()
	logger := NewLogger("debug")
	monitor := NewSecurityMonitor(config, logger)

	// Add event handler with proper synchronization
	handlerCalled := make(chan bool, 1)
	handler := &testSecurityEventHandler{
		callback: func(event SecurityEvent) {
			select {
			case handlerCalled <- true:
			default:
				// Channel already has a value, don't block
			}
		},
	}
	monitor.AddEventHandler(handler)

	monitor.RecordAuthenticationFailure("192.168.1.1", "test-agent", "/login", "test failure", nil)

	// Wait for event handler to be called with timeout
	select {
	case <-handlerCalled:
		// Success - handler was called
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected event handler to be called within timeout")
	}
}

// Test helper for security event handler
type testSecurityEventHandler struct {
	callback func(SecurityEvent)
}

func (h *testSecurityEventHandler) HandleSecurityEvent(event SecurityEvent) {
	h.callback(event)
}

func TestDefaultSecurityMonitorConfig(t *testing.T) {
	config := DefaultSecurityMonitorConfig()

	if config.MaxFailuresPerIP <= 0 {
		t.Error("Expected positive MaxFailuresPerIP")
	}
	if config.BlockDurationMinutes <= 0 {
		t.Error("Expected positive BlockDurationMinutes")
	}
	if config.CleanupIntervalMinutes <= 0 {
		t.Error("Expected positive CleanupIntervalMinutes")
	}
	if config.FailureWindowMinutes <= 0 {
		t.Error("Expected positive FailureWindowMinutes")
	}
}

func TestSecurityMonitorCleanup(t *testing.T) {
	config := DefaultSecurityMonitorConfig()
	config.CleanupIntervalMinutes = 1
	config.BlockDurationMinutes = 1
	config.RetentionHours = 1

	logger := NewLogger("debug")
	monitor := NewSecurityMonitor(config, logger)

	// Block an IP
	for i := 0; i < config.MaxFailuresPerIP; i++ {
		monitor.RecordAuthenticationFailure("192.168.1.99", "test-agent", "/login", "test", nil)
	}

	// Verify it's blocked
	if !monitor.IsIPBlocked("192.168.1.99") {
		t.Error("IP should be blocked")
	}

	// Wait a bit and check if it gets unblocked automatically
	time.Sleep(100 * time.Millisecond)

	// The IP should still be blocked since we haven't waited long enough
	if !monitor.IsIPBlocked("192.168.1.99") {
		t.Error("IP should still be blocked")
	}
}

func TestSecurityEventTypes(t *testing.T) {
	config := DefaultSecurityMonitorConfig()
	logger := NewLogger("debug")
	monitor := NewSecurityMonitor(config, logger)

	// Test different event types - just verify they don't panic
	monitor.RecordAuthenticationFailure("192.168.1.200", "test-agent", "/login", "invalid password", nil)
	monitor.RecordTokenValidationFailure("192.168.1.200", "test-agent", "/api", "expired token", "abc123")
	monitor.RecordRateLimitHit("192.168.1.200", "test-agent", "/api")

	details := map[string]interface{}{"pattern": "test"}
	monitor.RecordSuspiciousActivity("192.168.1.200", "test-agent", "/admin", "unusual pattern", "multiple failed logins", details)

	// Just verify GetSecurityMetrics doesn't panic
	_ = monitor.GetSecurityMetrics()
}
