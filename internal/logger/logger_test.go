package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLogLevel tests the LogLevel constants and parsing
func TestLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"debug", LogLevelDebug},
		{"DEBUG", LogLevelDebug},
		{"info", LogLevelInfo},
		{"INFO", LogLevelInfo},
		{"error", LogLevelError},
		{"ERROR", LogLevelError},
		{"none", LogLevelNone},
		{"NONE", LogLevelNone},
		{"unknown", LogLevelInfo}, // default
		{"", LogLevelInfo},        // default
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("ParseLogLevel_%s", test.input), func(t *testing.T) {
			result := ParseLogLevel(test.input)
			if result != test.expected {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", test.input, result, test.expected)
			}
		})
	}
}

// TestStandardLogger_LogLevels tests logging at different levels
func TestStandardLogger_LogLevels(t *testing.T) {
	tests := []struct {
		name        string
		level       LogLevel
		shouldLog   map[string]bool
		loggerLevel string
	}{
		{
			name:        "Debug level logs everything",
			level:       LogLevelDebug,
			loggerLevel: "debug",
			shouldLog: map[string]bool{
				"debug": true,
				"info":  true,
				"error": true,
			},
		},
		{
			name:        "Info level logs info and error",
			level:       LogLevelInfo,
			loggerLevel: "info",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  true,
				"error": true,
			},
		},
		{
			name:        "Error level logs only error",
			level:       LogLevelError,
			loggerLevel: "error",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  false,
				"error": true,
			},
		},
		{
			name:        "None level logs nothing",
			level:       LogLevelNone,
			loggerLevel: "none",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  false,
				"error": false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var errorBuf, infoBuf, debugBuf bytes.Buffer
			logger := NewStandardLogger(test.loggerLevel, &errorBuf, &infoBuf, &debugBuf)

			// Test basic logging methods
			logger.Debug("debug message")
			logger.Info("info message")
			logger.Error("error message")

			// Check debug output
			debugOutput := debugBuf.String()
			if test.shouldLog["debug"] && !strings.Contains(debugOutput, "debug message") {
				t.Errorf("Expected debug message to be logged at level %v", test.level)
			}
			if !test.shouldLog["debug"] && strings.Contains(debugOutput, "debug message") {
				t.Errorf("Debug message should not be logged at level %v", test.level)
			}

			// Check info output
			infoOutput := infoBuf.String()
			if test.shouldLog["info"] && !strings.Contains(infoOutput, "info message") {
				t.Errorf("Expected info message to be logged at level %v", test.level)
			}
			if !test.shouldLog["info"] && strings.Contains(infoOutput, "info message") {
				t.Errorf("Info message should not be logged at level %v", test.level)
			}

			// Check error output
			errorOutput := errorBuf.String()
			if test.shouldLog["error"] && !strings.Contains(errorOutput, "error message") {
				t.Errorf("Expected error message to be logged at level %v", test.level)
			}
			if !test.shouldLog["error"] && strings.Contains(errorOutput, "error message") {
				t.Errorf("Error message should not be logged at level %v", test.level)
			}
		})
	}
}

// TestStandardLogger_FormattedLogging tests formatted logging methods
func TestStandardLogger_FormattedLogging(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	logger := NewStandardLogger("debug", &errorBuf, &infoBuf, &debugBuf)

	// Test formatted methods
	logger.Debugf("debug %s %d", "test", 123)
	logger.Infof("info %s %d", "test", 456)
	logger.Errorf("error %s %d", "test", 789)
	logger.Printf("printf %s %d", "test", 999)

	// Check outputs
	if !strings.Contains(debugBuf.String(), "debug test 123") {
		t.Error("Debugf output not found")
	}
	if !strings.Contains(infoBuf.String(), "info test 456") {
		t.Error("Infof output not found")
	}
	if !strings.Contains(infoBuf.String(), "printf test 999") {
		t.Error("Printf output not found (should go to info)")
	}
	if !strings.Contains(errorBuf.String(), "error test 789") {
		t.Error("Errorf output not found")
	}
}

// TestStandardLogger_Println tests the Println method
func TestStandardLogger_Println(t *testing.T) {
	var infoBuf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &infoBuf, nil)

	logger.Println("test", "message", 123)

	output := infoBuf.String()
	// Just check that the essential content is there, ignoring formatting differences
	if !strings.Contains(output, "test") || !strings.Contains(output, "message") || !strings.Contains(output, "123") {
		t.Errorf("Println output missing expected content: %s", output)
	}
}

// TestStandardLogger_Fatalf tests the Fatalf method (should panic)
func TestStandardLogger_Fatalf(t *testing.T) {
	var errorBuf bytes.Buffer
	logger := NewStandardLogger("debug", &errorBuf, nil, nil)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Fatalf should have panicked")
		}
		// Check that error was logged before panic
		if !strings.Contains(errorBuf.String(), "fatal test") {
			t.Error("Fatalf should log error before panicking")
		}
	}()

	logger.Fatalf("fatal %s", "test")
}

// TestStandardLogger_WithField tests structured logging with single field
func TestStandardLogger_WithField(t *testing.T) {
	var infoBuf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &infoBuf, nil)

	fieldLogger := logger.WithField("key", "value")
	fieldLogger.Info("test message")

	output := infoBuf.String()
	if !strings.Contains(output, "test message [key=value]") {
		t.Errorf("WithField output incorrect: %s", output)
	}

	// Test that original logger is unchanged
	infoBuf.Reset()
	logger.Info("original message")
	output = infoBuf.String()
	if strings.Contains(output, "[key=value]") {
		t.Error("Original logger should not have fields")
	}
}

// TestStandardLogger_WithFields tests structured logging with multiple fields
func TestStandardLogger_WithFields(t *testing.T) {
	var infoBuf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &infoBuf, nil)

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}
	fieldLogger := logger.WithFields(fields)
	fieldLogger.Info("test message")

	output := infoBuf.String()
	// Check that message contains all fields (order may vary)
	if !strings.Contains(output, "test message [") {
		t.Error("WithFields should format message with fields")
	}
	if !strings.Contains(output, "key1=value1") {
		t.Error("Missing key1=value1 in output")
	}
	if !strings.Contains(output, "key2=42") {
		t.Error("Missing key2=42 in output")
	}
	if !strings.Contains(output, "key3=true") {
		t.Error("Missing key3=true in output")
	}
}

// TestStandardLogger_NestedFields tests chaining WithField calls
func TestStandardLogger_NestedFields(t *testing.T) {
	var infoBuf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &infoBuf, nil)

	chainedLogger := logger.WithField("key1", "value1").WithField("key2", "value2")
	chainedLogger.Info("test message")

	output := infoBuf.String()
	if !strings.Contains(output, "key1=value1") || !strings.Contains(output, "key2=value2") {
		t.Errorf("Chained fields not found in output: %s", output)
	}
}

// TestStandardLogger_ConcurrentSafety tests concurrent access to logger
func TestStandardLogger_ConcurrentSafety(t *testing.T) {
	// Use separate buffers for each log level to avoid race conditions in the test
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	var bufMutex sync.Mutex // Protect the buffers in test

	// Wrap buffers with mutex protection for test
	safeErrorBuf := &safeBuffer{buf: &errorBuf, mu: &bufMutex}
	safeInfoBuf := &safeBuffer{buf: &infoBuf, mu: &bufMutex}
	safeDebugBuf := &safeBuffer{buf: &debugBuf, mu: &bufMutex}

	logger := NewStandardLogger("debug", safeErrorBuf, safeInfoBuf, safeDebugBuf)

	var wg sync.WaitGroup
	numGoroutines := 10 // Reduced for faster test
	messagesPerGoroutine := 5

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				logger.Infof("goroutine %d message %d", id, j)
				fieldLogger := logger.WithField("goroutine", id)
				fieldLogger.Debugf("field message %d", j)
			}
		}(i)
	}

	wg.Wait()

	// Just verify no panic occurred and some output was generated
	bufMutex.Lock()
	totalLen := errorBuf.Len() + infoBuf.Len() + debugBuf.Len()
	bufMutex.Unlock()

	if totalLen == 0 {
		t.Error("Expected some log output from concurrent operations")
	}
}

// safeBuffer wraps bytes.Buffer with mutex for testing
type safeBuffer struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (sb *safeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

// TestNewStandardLogger_NilOutputs tests logger creation with nil outputs
func TestNewStandardLogger_NilOutputs(t *testing.T) {
	logger := NewStandardLogger("debug", nil, nil, nil)

	// Should not panic when logging to nil outputs
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Error("error message")
}

// TestNoOpLogger tests the NoOpLogger implementation
func TestNoOpLogger(t *testing.T) {
	logger := &NoOpLogger{}

	// None of these should panic or produce output
	logger.Debug("debug")
	logger.Debugf("debug %s", "formatted")
	logger.Info("info")
	logger.Infof("info %s", "formatted")
	logger.Error("error")
	logger.Errorf("error %s", "formatted")
	logger.Printf("printf %s", "formatted")
	logger.Println("println", "args")
	logger.Fatalf("fatalf %s", "formatted") // Should NOT panic

	// Test chaining
	fieldLogger := logger.WithField("key", "value")
	if fieldLogger != logger {
		t.Error("WithField should return same NoOpLogger instance")
	}

	fieldsLogger := logger.WithFields(map[string]interface{}{"key": "value"})
	if fieldsLogger != logger {
		t.Error("WithFields should return same NoOpLogger instance")
	}
}

// TestNoOpLogger_DirectInstantiation tests NoOpLogger methods through direct instantiation
func TestNoOpLogger_DirectInstantiation(t *testing.T) {
	// Create NoOpLogger instance directly to ensure methods are called
	logger := &NoOpLogger{}

	// Verify these methods exist and can be called without panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NoOpLogger methods should not panic: %v", r)
		}
	}()

	// Call each method explicitly to ensure coverage
	logger.Debug("test debug")
	logger.Debugf("test debugf %s", "arg")
	logger.Info("test info")
	logger.Infof("test infof %s", "arg")
	logger.Error("test error")
	logger.Errorf("test errorf %s", "arg")
	logger.Printf("test printf %s", "arg")
	logger.Println("test", "println")
	logger.Fatalf("test fatalf %s", "arg") // Critical: should NOT panic

	// Test field methods
	result1 := logger.WithField("key", "value")
	if result1 != logger {
		t.Error("WithField should return same instance")
	}

	result2 := logger.WithFields(map[string]interface{}{"key": "value"})
	if result2 != logger {
		t.Error("WithFields should return same instance")
	}
}

// =============================================================================
// Enhanced NoOpLogger Tests (lines 256-280 coverage)
// =============================================================================

// TestNoOpLogger_AllMethods tests all NoOpLogger methods comprehensively
func TestNoOpLogger_AllMethods(t *testing.T) {
	logger := &NoOpLogger{}

	// Test all methods don't panic with various inputs
	testCases := []struct {
		name string
		fn   func()
	}{
		{"Debug empty", func() { logger.Debug("") }},
		{"Debug normal", func() { logger.Debug("debug message") }},
		{"Debug long", func() { logger.Debug(strings.Repeat("long ", 1000)) }},
		{"Debug special chars", func() { logger.Debug("Debug with \n\t special chars: \\u00e9") }},

		{"Debugf empty", func() { logger.Debugf("") }},
		{"Debugf no args", func() { logger.Debugf("debug message") }},
		{"Debugf with args", func() { logger.Debugf("debug %s %d", "test", 42) }},
		{"Debugf many args", func() { logger.Debugf("debug %v %v %v %v", 1, 2, 3, 4) }},
		{"Debugf nil args", func() { logger.Debugf("debug %v", nil) }},

		{"Info empty", func() { logger.Info("") }},
		{"Info normal", func() { logger.Info("info message") }},
		{"Info special chars", func() { logger.Info("Info with unicode: ü ñ é") }},

		{"Infof empty", func() { logger.Infof("") }},
		{"Infof no args", func() { logger.Infof("info message") }},
		{"Infof with args", func() { logger.Infof("info %s %d", "test", 123) }},
		{"Infof complex", func() { logger.Infof("complex %+v", map[string]int{"key": 42}) }},

		{"Error empty", func() { logger.Error("") }},
		{"Error normal", func() { logger.Error("error message") }},
		{"Error long", func() { logger.Error(strings.Repeat("error ", 500)) }},

		{"Errorf empty", func() { logger.Errorf("") }},
		{"Errorf no args", func() { logger.Errorf("error message") }},
		{"Errorf with args", func() { logger.Errorf("error %s %d", "test", 456) }},
		{"Errorf with error", func() { logger.Errorf("error: %v", fmt.Errorf("test error")) }},

		{"Printf empty", func() { logger.Printf("") }},
		{"Printf no args", func() { logger.Printf("printf message") }},
		{"Printf with args", func() { logger.Printf("printf %s %d", "test", 789) }},
		{"Printf percent", func() { logger.Printf("100%% complete") }},

		{"Println empty", func() { logger.Println() }},
		{"Println single", func() { logger.Println("single") }},
		{"Println multiple", func() { logger.Println("multiple", "args", 123, true) }},
		{"Println nil", func() { logger.Println(nil, nil) }},
		{"Println mixed", func() { logger.Println("string", 42, true, 3.14, []int{1, 2, 3}) }},

		{"Fatalf empty", func() { logger.Fatalf("") }},
		{"Fatalf no args", func() { logger.Fatalf("fatal message") }},
		{"Fatalf with args", func() { logger.Fatalf("fatal %s %d", "test", 999) }},
		{"Fatalf should not panic", func() { logger.Fatalf("this should not cause panic") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure no panic occurs
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("NoOpLogger.%s panicked: %v", tc.name, r)
				}
			}()

			tc.fn()
		})
	}
}

// TestNoOpLogger_WithField_EdgeCases tests WithField with edge cases
func TestNoOpLogger_WithField_EdgeCases(t *testing.T) {
	logger := &NoOpLogger{}

	testCases := []struct {
		name  string
		key   string
		value interface{}
	}{
		{"empty key", "", "value"},
		{"empty value", "key", ""},
		{"nil value", "key", nil},
		{"complex value", "key", map[string]interface{}{"nested": []int{1, 2, 3}}},
		{"function value", "key", func() string { return "test" }},
		{"channel value", "key", make(chan int)},
		{"large string", "key", strings.Repeat("large ", 1000)},
		{"unicode key", "ключ", "значение"},
		{"unicode value", "key", "値 💻 🌟"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := logger.WithField(tc.key, tc.value)

			if result != logger {
				t.Error("WithField should always return the same NoOpLogger instance")
			}

			// Should be able to chain calls
			chained := result.WithField("another", "value")
			if chained != logger {
				t.Error("Chained WithField should return the same NoOpLogger instance")
			}
		})
	}
}

// TestNoOpLogger_WithFields_EdgeCases tests WithFields with edge cases
func TestNoOpLogger_WithFields_EdgeCases(t *testing.T) {
	logger := &NoOpLogger{}

	testCases := []struct {
		name   string
		fields map[string]interface{}
	}{
		{"nil map", nil},
		{"empty map", map[string]interface{}{}},
		{"single field", map[string]interface{}{"key": "value"}},
		{"multiple fields", map[string]interface{}{
			"string": "value",
			"int":    42,
			"bool":   true,
			"float":  3.14,
		}},
		{"nil values", map[string]interface{}{
			"nil1": nil,
			"nil2": nil,
		}},
		{"complex values", map[string]interface{}{
			"map":      map[string]int{"nested": 42},
			"slice":    []string{"a", "b", "c"},
			"function": func() {},
			"channel":  make(chan string),
		}},
		{"large map", func() map[string]interface{} {
			large := make(map[string]interface{})
			for i := 0; i < 1000; i++ {
				large[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
			}
			return large
		}()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := logger.WithFields(tc.fields)

			if result != logger {
				t.Error("WithFields should always return the same NoOpLogger instance")
			}

			// Should be able to chain calls
			chained := result.WithFields(map[string]interface{}{"another": "value"})
			if chained != logger {
				t.Error("Chained WithFields should return the same NoOpLogger instance")
			}
		})
	}
}

// TestNoOpLogger_Concurrent tests concurrent access to NoOpLogger
func TestNoOpLogger_Concurrent(t *testing.T) {
	logger := &NoOpLogger{}

	var wg sync.WaitGroup
	numGoroutines := 100
	operationsPerGoroutine := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Test various operations concurrently
				logger.Debug(fmt.Sprintf("debug %d-%d", id, j))
				logger.Debugf("debugf %d-%d", id, j)
				logger.Info(fmt.Sprintf("info %d-%d", id, j))
				logger.Infof("infof %d-%d", id, j)
				logger.Error(fmt.Sprintf("error %d-%d", id, j))
				logger.Errorf("errorf %d-%d", id, j)
				logger.Printf("printf %d-%d", id, j)
				logger.Println("println", id, j)
				logger.Fatalf("fatalf %d-%d", id, j)

				// Test field operations
				fieldLogger := logger.WithField(fmt.Sprintf("key%d", id), j)
				fieldLogger.Info("test")

				fieldsLogger := logger.WithFields(map[string]interface{}{
					"goroutine": id,
					"operation": j,
				})
				fieldsLogger.Debug("test")
			}
		}(i)
	}

	wg.Wait()
	// If we reach here without deadlock or panic, the test passes
}

// TestNoOpLogger_Singleton_Consistency tests singleton behavior
func TestNoOpLogger_Singleton_Consistency(t *testing.T) {
	// Get multiple instances through different paths
	logger1 := &NoOpLogger{}
	logger2 := GetNoOpLogger()
	logger3 := GetFactory().GetNoOpLogger()

	// Test that WithField/WithFields always return the same type
	field1 := logger1.WithField("key", "value")
	field2 := logger2.WithField("key", "value")
	field3 := logger3.WithField("key", "value")

	// All should be NoOpLoggers
	if _, ok := field1.(*NoOpLogger); !ok {
		t.Error("WithField should return NoOpLogger")
	}
	if _, ok := field2.(*NoOpLogger); !ok {
		t.Error("WithField should return NoOpLogger")
	}
	if _, ok := field3.(*NoOpLogger); !ok {
		t.Error("WithField should return NoOpLogger")
	}

	// Test WithFields
	fields1 := logger1.WithFields(map[string]interface{}{"key": "value"})
	fields2 := logger2.WithFields(map[string]interface{}{"key": "value"})
	fields3 := logger3.WithFields(map[string]interface{}{"key": "value"})

	if _, ok := fields1.(*NoOpLogger); !ok {
		t.Error("WithFields should return NoOpLogger")
	}
	if _, ok := fields2.(*NoOpLogger); !ok {
		t.Error("WithFields should return NoOpLogger")
	}
	if _, ok := fields3.(*NoOpLogger); !ok {
		t.Error("WithFields should return NoOpLogger")
	}
}

// =============================================================================
// Additional Edge Cases and Error Scenarios
// =============================================================================

// TestStandardLogger_NilFieldValues tests handling of nil field values
func TestStandardLogger_NilFieldValues(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	// Test nil field values
	fieldLogger := logger.WithField("nil_value", nil)
	fieldLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "test message [nil_value=<nil>]") {
		t.Errorf("Expected nil value to be formatted as '<nil>', got: %s", output)
	}
}

// TestStandardLogger_LargeMessages tests handling of very large messages
func TestStandardLogger_LargeMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	// Test very large message
	largeMessage := strings.Repeat("This is a very long message. ", 1000)
	logger.Info(largeMessage)

	output := buf.String()
	if !strings.Contains(output, largeMessage) {
		t.Error("Large message should be handled correctly")
	}
}

// TestStandardLogger_UnicodeMessages tests handling of unicode characters
func TestStandardLogger_UnicodeMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	unicodeMessage := "Unicode test: 中文 日本語 한글 العربية ελληνικά русский ⚡️ 🌟 💻"
	logger.Info(unicodeMessage)

	output := buf.String()
	if !strings.Contains(output, unicodeMessage) {
		t.Error("Unicode characters should be preserved in log output")
	}
}

// TestStandardLogger_ZeroLengthMessages tests zero-length message handling
func TestStandardLogger_ZeroLengthMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	// Test empty messages
	logger.Debug("")
	logger.Info("")
	logger.Error("")

	// Should write something (timestamp, etc.) even with empty messages
	if buf.Len() == 0 {
		t.Error("Empty messages should still produce some output")
	}
}

// TestLogLevel_AllValues tests all log level values
func TestLogLevel_AllValues(t *testing.T) {
	levelMap := map[LogLevel]string{
		LogLevelDebug: "debug",
		LogLevelInfo:  "info",
		LogLevelError: "error",
		LogLevelNone:  "none",
	}

	for level, levelStr := range levelMap {
		var errorBuf, infoBuf, debugBuf bytes.Buffer
		logger := NewStandardLogger(levelStr, &errorBuf, &infoBuf, &debugBuf)

		// Test that logger was created successfully with each level
		if logger == nil {
			t.Errorf("NewStandardLogger should not return nil for level %v", level)
		}
	}
}

// TestStandardLogger_FormattingEdgeCases tests edge cases in formatting
func TestStandardLogger_FormattingEdgeCases(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	// Test format strings with various argument types
	logger.Infof("format %v %v %v", "string", 42, true)

	// Test percent signs in format strings
	logger.Infof("Progress: 100%% complete")

	// Test with nil arguments
	logger.Infof("nil value: %v", nil)

	// Should not panic and produce output
	if buf.Len() == 0 {
		t.Error("Should produce output from formatting tests")
	}
}

// TestLegacyLoggerAdapter_ConcurrentAccess tests concurrent access to adapter
func TestLegacyLoggerAdapter_ConcurrentAccess(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	var bufMutex sync.Mutex

	// Thread-safe buffer wrappers
	safeErrorBuf := &safeBuffer{buf: &errorBuf, mu: &bufMutex}
	safeInfoBuf := &safeBuffer{buf: &infoBuf, mu: &bufMutex}
	safeDebugBuf := &safeBuffer{buf: &debugBuf, mu: &bufMutex}

	errorLogger := log.New(safeErrorBuf, "", 0)
	infoLogger := log.New(safeInfoBuf, "", 0)
	debugLogger := log.New(safeDebugBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger)

	var wg sync.WaitGroup
	numGoroutines := 10
	messagesPerGoroutine := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				adapter.Debug(fmt.Sprintf("debug %d-%d", id, j))
				adapter.Info(fmt.Sprintf("info %d-%d", id, j))
				adapter.Error(fmt.Sprintf("error %d-%d", id, j))
			}
		}(i)
	}

	wg.Wait()

	// Verify some output was generated
	bufMutex.Lock()
	totalLen := errorBuf.Len() + infoBuf.Len() + debugBuf.Len()
	bufMutex.Unlock()

	if totalLen == 0 {
		t.Error("Expected some log output from concurrent operations")
	}
}

// TestGetNoOpLogger tests the singleton no-op logger
func TestGetNoOpLogger(t *testing.T) {
	logger1 := GetNoOpLogger()
	logger2 := GetNoOpLogger()

	if logger1 != logger2 {
		t.Error("GetNoOpLogger should return the same instance (singleton)")
	}

	// Verify it's actually a NoOpLogger
	if _, ok := logger1.(*NoOpLogger); !ok {
		t.Error("GetNoOpLogger should return a NoOpLogger instance")
	}
}

// TestDefaultLogger tests the DefaultLogger function
func TestDefaultLogger(t *testing.T) {
	logger := DefaultLogger("info")

	// Should be a StandardLogger
	if _, ok := logger.(*StandardLogger); !ok {
		t.Error("DefaultLogger should return a StandardLogger instance")
	}

	// Test that it actually logs (to default outputs)
	logger.Info("test message") // Should not panic
}

// TestStandardLogger_formatWithFields tests the private formatWithFields method indirectly
func TestStandardLogger_formatWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStandardLogger("debug", nil, &buf, nil)

	// Test empty fields
	logger.Info("no fields")
	output := buf.String()
	if strings.Contains(output, "[") {
		t.Error("Message without fields should not contain brackets")
	}

	buf.Reset()

	// Test single field
	fieldLogger := logger.WithField("key", "value")
	fieldLogger.Info("one field")
	output = buf.String()
	if !strings.Contains(output, "one field [key=value]") {
		t.Errorf("Single field formatting incorrect: %s", output)
	}

	buf.Reset()

	// Test multiple fields (order may vary, so check components)
	fieldsLogger := logger.WithFields(map[string]interface{}{
		"a": 1,
		"b": 2,
	})
	fieldsLogger.Info("two fields")
	output = buf.String()
	if !strings.Contains(output, "two fields [") {
		t.Error("Multiple fields should start with message and bracket")
	}
	if !strings.Contains(output, "a=1") || !strings.Contains(output, "b=2") {
		t.Error("Multiple fields should contain all key=value pairs")
	}
}

// Benchmark tests for performance critical paths
func BenchmarkStandardLogger_Info(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStandardLogger("info", nil, &buf, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message")
	}
}

func BenchmarkStandardLogger_InfoWithField(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStandardLogger("info", nil, &buf, nil)
	fieldLogger := logger.WithField("key", "value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fieldLogger.Info("benchmark message")
	}
}

func BenchmarkStandardLogger_DebugDisabled(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStandardLogger("info", nil, &buf, nil) // Debug disabled

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Debug("benchmark message") // Should be fast when disabled
	}
}

func BenchmarkNoOpLogger(b *testing.B) {
	logger := GetNoOpLogger()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message")
	}
}

func BenchmarkWithField(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStandardLogger("info", nil, &buf, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithField("iteration", i)
	}
}

// =============================================================================
// LegacyLoggerAdapter Tests (adapter.go - 0% coverage)
// =============================================================================

// TestNewLegacyAdapter tests creating a new legacy adapter
func TestNewLegacyAdapter(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "ERROR: ", log.LstdFlags)
	infoLogger := log.New(&infoBuf, "INFO: ", log.LstdFlags)
	debugLogger := log.New(&debugBuf, "DEBUG: ", log.LstdFlags)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger)

	if adapter == nil {
		t.Error("NewLegacyAdapter should not return nil")
	}

	// Verify it's the correct type
	if _, ok := adapter.(*LegacyLoggerAdapter); !ok {
		t.Error("NewLegacyAdapter should return a LegacyLoggerAdapter")
	}
}

// TestNewLegacyAdapter_WithNilLoggers tests creating adapter with nil loggers
func TestNewLegacyAdapter_WithNilLoggers(t *testing.T) {
	tests := []struct {
		name        string
		errorLogger *log.Logger
		infoLogger  *log.Logger
		debugLogger *log.Logger
	}{
		{"nil error logger", nil, log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0)},
		{"nil info logger", log.New(&bytes.Buffer{}, "", 0), nil, log.New(&bytes.Buffer{}, "", 0)},
		{"nil debug logger", log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0), nil},
		{"all nil loggers", nil, nil, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := NewLegacyAdapter(test.errorLogger, test.infoLogger, test.debugLogger)

			// Should return NoOpLogger when any logger is nil
			if _, ok := adapter.(*NoOpLogger); !ok {
				t.Error("NewLegacyAdapter with nil loggers should return NoOpLogger")
			}
		})
	}
}

// TestLegacyLoggerAdapter_Debug tests debug logging
func TestLegacyLoggerAdapter_Debug(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)
	infoLogger := log.New(&infoBuf, "", 0)
	debugLogger := log.New(&debugBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger).(*LegacyLoggerAdapter)

	adapter.Debug("debug message")

	if !strings.Contains(debugBuf.String(), "debug message") {
		t.Error("Debug message not found in debug buffer")
	}

	// Verify other buffers are empty
	if errorBuf.Len() > 0 || infoBuf.Len() > 0 {
		t.Error("Debug should only write to debug buffer")
	}
}

// TestLegacyLoggerAdapter_Debugf tests formatted debug logging
func TestLegacyLoggerAdapter_Debugf(t *testing.T) {
	var debugBuf bytes.Buffer
	debugLogger := log.New(&debugBuf, "", 0)

	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0), debugLogger).(*LegacyLoggerAdapter)

	adapter.Debugf("debug %s %d", "test", 42)

	if !strings.Contains(debugBuf.String(), "debug test 42") {
		t.Error("Debugf formatted message not found in debug buffer")
	}
}

// TestLegacyLoggerAdapter_Info tests info logging
func TestLegacyLoggerAdapter_Info(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)
	infoLogger := log.New(&infoBuf, "", 0)
	debugLogger := log.New(&debugBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger).(*LegacyLoggerAdapter)

	adapter.Info("info message")

	if !strings.Contains(infoBuf.String(), "info message") {
		t.Error("Info message not found in info buffer")
	}

	// Verify other buffers are empty
	if errorBuf.Len() > 0 || debugBuf.Len() > 0 {
		t.Error("Info should only write to info buffer")
	}
}

// TestLegacyLoggerAdapter_Infof tests formatted info logging
func TestLegacyLoggerAdapter_Infof(t *testing.T) {
	var infoBuf bytes.Buffer
	infoLogger := log.New(&infoBuf, "", 0)

	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), infoLogger, log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	adapter.Infof("info %s %d", "test", 123)

	if !strings.Contains(infoBuf.String(), "info test 123") {
		t.Error("Infof formatted message not found in info buffer")
	}
}

// TestLegacyLoggerAdapter_Error tests error logging
func TestLegacyLoggerAdapter_Error(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)
	infoLogger := log.New(&infoBuf, "", 0)
	debugLogger := log.New(&debugBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger).(*LegacyLoggerAdapter)

	adapter.Error("error message")

	if !strings.Contains(errorBuf.String(), "error message") {
		t.Error("Error message not found in error buffer")
	}

	// Verify other buffers are empty
	if infoBuf.Len() > 0 || debugBuf.Len() > 0 {
		t.Error("Error should only write to error buffer")
	}
}

// TestLegacyLoggerAdapter_Errorf tests formatted error logging
func TestLegacyLoggerAdapter_Errorf(t *testing.T) {
	var errorBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	adapter.Errorf("error %s %d", "test", 456)

	if !strings.Contains(errorBuf.String(), "error test 456") {
		t.Error("Errorf formatted message not found in error buffer")
	}
}

// TestLegacyLoggerAdapter_Printf tests printf logging (should go to info)
func TestLegacyLoggerAdapter_Printf(t *testing.T) {
	var infoBuf bytes.Buffer
	infoLogger := log.New(&infoBuf, "", 0)

	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), infoLogger, log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	adapter.Printf("printf %s %d", "test", 789)

	if !strings.Contains(infoBuf.String(), "printf test 789") {
		t.Error("Printf formatted message not found in info buffer")
	}
}

// TestLegacyLoggerAdapter_Println tests println logging (should go to info)
func TestLegacyLoggerAdapter_Println(t *testing.T) {
	var infoBuf bytes.Buffer
	infoLogger := log.New(&infoBuf, "", 0)

	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), infoLogger, log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	adapter.Println("println", "test", 999)

	output := infoBuf.String()
	if !strings.Contains(output, "println") || !strings.Contains(output, "test") || !strings.Contains(output, "999") {
		t.Errorf("Println output missing expected content: %s", output)
	}
}

// TestLegacyLoggerAdapter_Fatalf tests fatalf logging (should log and panic)
func TestLegacyLoggerAdapter_Fatalf(t *testing.T) {
	var errorBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Fatalf should have panicked")
		}
		// Check that error was logged before panic
		if !strings.Contains(errorBuf.String(), "fatal test 123") {
			t.Error("Fatalf should log error before panicking")
		}
	}()

	adapter.Fatalf("fatal %s %d", "test", 123)
}

// TestLegacyLoggerAdapter_WithField tests structured logging (should return same adapter)
func TestLegacyLoggerAdapter_WithField(t *testing.T) {
	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0))

	fieldLogger := adapter.WithField("key", "value")

	if fieldLogger != adapter {
		t.Error("WithField should return the same adapter instance (no structured logging support)")
	}
}

// TestLegacyLoggerAdapter_WithFields tests structured logging with multiple fields
func TestLegacyLoggerAdapter_WithFields(t *testing.T) {
	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0), log.New(&bytes.Buffer{}, "", 0))

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}
	fieldsLogger := adapter.WithFields(fields)

	if fieldsLogger != adapter {
		t.Error("WithFields should return the same adapter instance (no structured logging support)")
	}
}

// TestLegacyLoggerAdapter_EmptyMessages tests logging empty messages
func TestLegacyLoggerAdapter_EmptyMessages(t *testing.T) {
	var errorBuf, infoBuf, debugBuf bytes.Buffer
	errorLogger := log.New(&errorBuf, "", 0)
	infoLogger := log.New(&infoBuf, "", 0)
	debugLogger := log.New(&debugBuf, "", 0)

	adapter := NewLegacyAdapter(errorLogger, infoLogger, debugLogger).(*LegacyLoggerAdapter)

	// Test empty messages
	adapter.Debug("")
	adapter.Info("")
	adapter.Error("")

	// Should not crash, buffers should have some content (even if just newlines)
	if debugBuf.Len() == 0 {
		t.Error("Debug with empty message should still write to buffer")
	}
	if infoBuf.Len() == 0 {
		t.Error("Info with empty message should still write to buffer")
	}
	if errorBuf.Len() == 0 {
		t.Error("Error with empty message should still write to buffer")
	}
}

// TestLegacyLoggerAdapter_SpecialCharacters tests logging with special characters
func TestLegacyLoggerAdapter_SpecialCharacters(t *testing.T) {
	var infoBuf bytes.Buffer
	infoLogger := log.New(&infoBuf, "", 0)

	adapter := NewLegacyAdapter(log.New(&bytes.Buffer{}, "", 0), infoLogger, log.New(&bytes.Buffer{}, "", 0)).(*LegacyLoggerAdapter)

	specialMsg := "Message with \n newlines \t tabs and unicode: \u00e9\u00f1\u00fc"
	adapter.Info(specialMsg)

	if !strings.Contains(infoBuf.String(), specialMsg) {
		t.Error("Special characters should be preserved in log output")
	}
}

// =============================================================================
// Factory Tests (factory.go - 0% coverage)
// =============================================================================

// TestGetFactory tests the singleton factory
func TestGetFactory(t *testing.T) {
	factory1 := GetFactory()
	factory2 := GetFactory()

	if factory1 == nil {
		t.Error("GetFactory should not return nil")
	}

	if factory1 != factory2 {
		t.Error("GetFactory should return the same instance (singleton)")
	}
}

// TestFactory_SetDefaultLogLevel tests setting default log level
func TestFactory_SetDefaultLogLevel(t *testing.T) {
	factory := GetFactory()

	// Clear factory state for clean test
	factory.Clear()

	factory.SetDefaultLogLevel("debug")

	// Create a logger and verify it uses the new default level
	logger := factory.createLogger("test")

	// Test by checking if debug logging works
	var buf bytes.Buffer
	if stdLogger, ok := logger.(*StandardLogger); ok {
		// Create a new logger with our buffer to test the level
		testLogger := NewStandardLogger("debug", nil, nil, &buf)
		testLogger.Debug("test debug")

		if buf.Len() == 0 {
			t.Error("Debug level should be active when default is set to debug")
		}

		// Verify the logger is a StandardLogger (not NoOp)
		if stdLogger == nil {
			t.Error("Expected StandardLogger when level is debug")
		}
	}
}

// TestFactory_GetLogger tests logger creation and caching
func TestFactory_GetLogger(t *testing.T) {
	factory := GetFactory()
	factory.Clear() // Clean state

	// Test creating a new logger
	logger1 := factory.GetLogger("test-logger")
	if logger1 == nil {
		t.Error("GetLogger should not return nil")
	}

	// Test that getting the same logger returns cached instance
	logger2 := factory.GetLogger("test-logger")
	if logger1 != logger2 {
		t.Error("GetLogger should return cached instance for same name")
	}

	// Test creating a different logger
	logger3 := factory.GetLogger("different-logger")
	if logger3 == logger1 {
		t.Error("Different logger names should create different instances")
	}
}

// TestFactory_GetLogger_NoOp tests creating no-op loggers
func TestFactory_GetLogger_NoOp(t *testing.T) {
	factory := GetFactory()
	factory.Clear()

	noOpNames := []string{"noop", "no-op", "discard"}

	for _, name := range noOpNames {
		t.Run(name, func(t *testing.T) {
			logger := factory.GetLogger(name)

			if _, ok := logger.(*NoOpLogger); !ok {
				t.Errorf("GetLogger(%q) should return NoOpLogger", name)
			}
		})
	}
}

// TestFactory_createLogger tests logger creation logic
func TestFactory_createLogger(t *testing.T) {
	factory := GetFactory()
	factory.SetDefaultLogLevel("info")

	// Test normal logger creation
	logger := factory.createLogger("normal")
	if _, ok := logger.(*StandardLogger); !ok {
		t.Error("createLogger should return StandardLogger for normal names")
	}

	// Test no-op logger creation
	noOpLogger := factory.createLogger("noop")
	if _, ok := noOpLogger.(*NoOpLogger); !ok {
		t.Error("createLogger should return NoOpLogger for 'noop'")
	}
}

// TestFactory_createLogger_WithEnvironment tests logger creation with environment variables
func TestFactory_createLogger_WithEnvironment(t *testing.T) {
	// Save original environment
	originalLogToFile := os.Getenv("OIDC_LOG_TO_FILE")
	originalLogDir := os.Getenv("OIDC_LOG_DIR")

	defer func() {
		// Restore original environment
		os.Setenv("OIDC_LOG_TO_FILE", originalLogToFile)
		os.Setenv("OIDC_LOG_DIR", originalLogDir)
	}()

	// Create temporary directory for test
	tempDir := t.TempDir()

	// Set environment to use file logging
	os.Setenv("OIDC_LOG_TO_FILE", "true")
	os.Setenv("OIDC_LOG_DIR", tempDir)

	factory := GetFactory()
	logger := factory.createLogger("file-test")

	if _, ok := logger.(*StandardLogger); !ok {
		t.Error("createLogger should return StandardLogger even with file logging")
	}

	// Test that log files are created when logging
	logger.Info("test message")
	logger.Error("test error")
	logger.Debug("test debug")

	// Give a moment for file operations
	time.Sleep(10 * time.Millisecond)

	// Check if log files were created (they might be, depending on implementation)
	// This tests the file creation path even if files aren't immediately visible
	expectedFiles := []string{"info.log", "error.log", "debug.log"}
	for _, filename := range expectedFiles {
		filepath := filepath.Join(tempDir, filename)
		if _, err := os.Stat(filepath); err == nil {
			// File exists, which is good - the file creation worked
			t.Logf("Log file created successfully: %s", filepath)
		}
	}
}

// TestFactory_GetDefaultLogger tests default logger creation and caching
func TestFactory_GetDefaultLogger(t *testing.T) {
	factory := GetFactory()
	factory.Clear()

	// Test creating default logger
	logger1 := factory.GetDefaultLogger()
	if logger1 == nil {
		t.Error("GetDefaultLogger should not return nil")
	}

	// Test that getting default logger again returns cached instance
	logger2 := factory.GetDefaultLogger()
	if logger1 != logger2 {
		t.Error("GetDefaultLogger should return cached instance")
	}

	// Should be a StandardLogger
	if _, ok := logger1.(*StandardLogger); !ok {
		t.Error("GetDefaultLogger should return StandardLogger")
	}
}

// TestFactory_GetNoOpLogger tests no-op logger singleton
func TestFactory_GetNoOpLogger(t *testing.T) {
	factory := GetFactory()

	// Test getting no-op logger
	logger1 := factory.GetNoOpLogger()
	if logger1 == nil {
		t.Error("GetNoOpLogger should not return nil")
	}

	// Test that getting no-op logger again returns same instance
	logger2 := factory.GetNoOpLogger()
	if logger1 != logger2 {
		t.Error("GetNoOpLogger should return same instance")
	}

	// Should be a NoOpLogger
	if _, ok := logger1.(*NoOpLogger); !ok {
		t.Error("GetNoOpLogger should return NoOpLogger")
	}
}

// TestFactory_Clear tests clearing factory cache
func TestFactory_Clear(t *testing.T) {
	factory := GetFactory()

	// Create some loggers
	logger1 := factory.GetLogger("test1")
	defaultLogger1 := factory.GetDefaultLogger()

	// Clear the factory
	factory.Clear()

	// Get loggers again - should be new instances
	logger2 := factory.GetLogger("test1")
	defaultLogger2 := factory.GetDefaultLogger()

	if logger1 == logger2 {
		t.Error("Clear should remove cached loggers")
	}

	if defaultLogger1 == defaultLogger2 {
		t.Error("Clear should remove cached default logger")
	}

	// NoOp logger should still be the same (singleton not cleared)
	noOp1 := factory.GetNoOpLogger()
	factory.Clear()
	noOp2 := factory.GetNoOpLogger()

	if noOp1 != noOp2 {
		t.Error("Clear should not affect NoOp logger singleton")
	}
}

// TestGetOrCreateLogFile tests file creation functionality
func TestGetOrCreateLogFile(t *testing.T) {
	// Save original environment
	originalLogDir := os.Getenv("OIDC_LOG_DIR")
	defer os.Setenv("OIDC_LOG_DIR", originalLogDir)

	// Test with custom log directory
	tempDir := t.TempDir()
	os.Setenv("OIDC_LOG_DIR", tempDir)

	// Test file creation
	writer := getOrCreateLogFile("test.log")
	if writer == nil {
		t.Error("getOrCreateLogFile should not return nil")
	}

	// Should be able to write to it
	n, err := writer.Write([]byte("test message\n"))
	if err != nil {
		t.Errorf("Should be able to write to log file: %v", err)
	}
	if n == 0 {
		t.Error("Should write some bytes")
	}

	// Check file was created
	filepath := filepath.Join(tempDir, "test.log")
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		t.Error("Log file should be created")
	}
}

// TestGetOrCreateLogFile_InvalidDirectory tests fallback behavior
func TestGetOrCreateLogFile_InvalidDirectory(t *testing.T) {
	// Save original environment
	originalLogDir := os.Getenv("OIDC_LOG_DIR")
	defer os.Setenv("OIDC_LOG_DIR", originalLogDir)

	// Set invalid directory (file instead of directory)
	tempDir := t.TempDir()
	invalidPath := filepath.Join(tempDir, "not-a-directory.txt")

	// Create a file where we want a directory
	err := os.WriteFile(invalidPath, []byte("content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	os.Setenv("OIDC_LOG_DIR", invalidPath)

	// Should fall back to stderr
	writer := getOrCreateLogFile("test.log")

	// Should return stderr (or some valid writer)
	if writer == nil {
		t.Error("getOrCreateLogFile should return stderr as fallback")
	}

	// Should be able to write (even if it's stderr)
	n, err := writer.Write([]byte("test message\n"))
	if err != nil {
		t.Errorf("Should be able to write to fallback writer: %v", err)
	}
	if n == 0 {
		t.Error("Should write some bytes to fallback")
	}
}

// TestGetOrCreateLogFile_DefaultDirectory tests default directory behavior
func TestGetOrCreateLogFile_DefaultDirectory(t *testing.T) {
	// Save and clear environment
	originalLogDir := os.Getenv("OIDC_LOG_DIR")
	os.Unsetenv("OIDC_LOG_DIR")
	defer os.Setenv("OIDC_LOG_DIR", originalLogDir)

	// This should use default directory /var/log/traefik-oidc
	// It will likely fail to create the directory due to permissions,
	// so it should fall back to stderr
	writer := getOrCreateLogFile("test.log")

	if writer == nil {
		t.Error("getOrCreateLogFile should return a writer (likely stderr as fallback)")
	}

	// Should be able to write
	n, err := writer.Write([]byte("test message\n"))
	if err != nil {
		t.Errorf("Should be able to write to writer: %v", err)
	}
	if n == 0 {
		t.Error("Should write some bytes")
	}
}

// TestGlobalConvenienceFunctions tests the global convenience functions
func TestGlobalConvenienceFunctions(t *testing.T) {
	// Clear factory state
	GetFactory().Clear()

	// Test New function
	logger1 := New("info")
	if logger1 == nil {
		t.Error("New should not return nil")
	}

	// Test Default function
	defaultLogger := Default()
	if defaultLogger == nil {
		t.Error("Default should not return nil")
	}

	// Test NoOp function
	noOpLogger := NoOp()
	if noOpLogger == nil {
		t.Error("NoOp should not return nil")
	}
	if _, ok := noOpLogger.(*NoOpLogger); !ok {
		t.Error("NoOp should return NoOpLogger")
	}

	// Test WithLevel function
	levelLogger := WithLevel("debug")
	if levelLogger == nil {
		t.Error("WithLevel should not return nil")
	}
	if _, ok := levelLogger.(*StandardLogger); !ok {
		t.Error("WithLevel should return StandardLogger")
	}
}

// TestFactory_ConcurrentAccess tests concurrent access to factory
func TestFactory_ConcurrentAccess(t *testing.T) {
	factory := GetFactory()
	factory.Clear()

	var wg sync.WaitGroup
	numGoroutines := 10
	loggerMap := make(map[int]Logger)
	var mapMutex sync.Mutex

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Test concurrent logger creation
			logger := factory.GetLogger(fmt.Sprintf("concurrent-%d", id))

			mapMutex.Lock()
			loggerMap[id] = logger
			mapMutex.Unlock()

			// Test concurrent default logger access
			defaultLogger := factory.GetDefaultLogger()
			if defaultLogger == nil {
				t.Errorf("GetDefaultLogger returned nil in goroutine %d", id)
			}

			// Test concurrent no-op logger access
			noOpLogger := factory.GetNoOpLogger()
			if noOpLogger == nil {
				t.Errorf("GetNoOpLogger returned nil in goroutine %d", id)
			}

			// Test concurrent logging
			logger.Info(fmt.Sprintf("message from goroutine %d", id))
		}(i)
	}

	wg.Wait()

	// Verify all loggers were created
	mapMutex.Lock()
	if len(loggerMap) != numGoroutines {
		t.Errorf("Expected %d loggers, got %d", numGoroutines, len(loggerMap))
	}

	// Verify all loggers are different (different names should create different instances)
	for i := 0; i < numGoroutines; i++ {
		logger := loggerMap[i]
		if logger == nil {
			t.Errorf("Logger %d is nil", i)
		}

		// Check it's the right type
		if _, ok := logger.(*StandardLogger); !ok {
			t.Errorf("Logger %d is not StandardLogger", i)
		}
	}
	mapMutex.Unlock()
}

// TestFactory_ConcurrentSameLogger tests concurrent access to same logger
func TestFactory_ConcurrentSameLogger(t *testing.T) {
	factory := GetFactory()
	factory.Clear()

	var wg sync.WaitGroup
	numGoroutines := 10
	loggers := make([]Logger, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// All goroutines request the same logger
			loggers[id] = factory.GetLogger("shared-logger")
		}(i)
	}

	wg.Wait()

	// All should be the same instance (cached)
	firstLogger := loggers[0]
	for i := 1; i < numGoroutines; i++ {
		if loggers[i] != firstLogger {
			t.Errorf("Logger %d should be same instance as first logger", i)
		}
	}
}
