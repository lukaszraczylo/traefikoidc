// Package logger provides a unified logging interface for the entire application.
// It consolidates all the duplicate logger interfaces into a single, comprehensive
// interface that supports different log levels and structured logging.
package logger

import (
	"fmt"
	"io"
	"log"
	"sync"
)

// Logger is the unified interface for all logging operations in the application.
// It combines all the methods from the various logger interfaces that were
// previously scattered across different packages.
type Logger interface {
	// Basic logging methods
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})

	// Additional methods for compatibility with existing code
	Printf(format string, args ...interface{})
	Println(args ...interface{})
	Fatalf(format string, args ...interface{})

	// Structured logging support
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
}

// StandardLogger implements the Logger interface using Go's standard log package.
// It provides thread-safe logging with different output streams for different log levels.
type StandardLogger struct {
	mu       sync.RWMutex
	logError *log.Logger
	logInfo  *log.Logger
	logDebug *log.Logger
	fields   map[string]interface{}
	level    LogLevel
}

// LogLevel represents the logging level
type LogLevel int

const (
	// LogLevelDebug enables all log messages
	LogLevelDebug LogLevel = iota
	// LogLevelInfo enables info and error messages
	LogLevelInfo
	// LogLevelError enables only error messages
	LogLevelError
	// LogLevelNone disables all logging
	LogLevelNone
)

// ParseLogLevel converts a string log level to LogLevel
func ParseLogLevel(level string) LogLevel {
	switch level {
	case "debug", "DEBUG":
		return LogLevelDebug
	case "info", "INFO":
		return LogLevelInfo
	case "error", "ERROR":
		return LogLevelError
	case "none", "NONE":
		return LogLevelNone
	default:
		return LogLevelInfo
	}
}

// NewStandardLogger creates a new StandardLogger with the specified log level
func NewStandardLogger(level string, errorOutput, infoOutput, debugOutput io.Writer) *StandardLogger {
	logLevel := ParseLogLevel(level)

	if errorOutput == nil {
		errorOutput = io.Discard
	}
	if infoOutput == nil {
		infoOutput = io.Discard
	}
	if debugOutput == nil {
		debugOutput = io.Discard
	}

	return &StandardLogger{
		logError: log.New(errorOutput, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		logInfo:  log.New(infoOutput, "INFO: ", log.Ldate|log.Ltime),
		logDebug: log.New(debugOutput, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
		fields:   make(map[string]interface{}),
		level:    logLevel,
	}
}

// Debug logs a debug message
func (l *StandardLogger) Debug(msg string) {
	if l.level <= LogLevelDebug {
		l.mu.RLock()
		defer l.mu.RUnlock()
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logDebug.Print(msg)
	}
}

// Debugf logs a formatted debug message
func (l *StandardLogger) Debugf(format string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.mu.RLock()
		defer l.mu.RUnlock()
		msg := fmt.Sprintf(format, args...)
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logDebug.Print(msg)
	}
}

// Info logs an info message
func (l *StandardLogger) Info(msg string) {
	if l.level <= LogLevelInfo {
		l.mu.RLock()
		defer l.mu.RUnlock()
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logInfo.Print(msg)
	}
}

// Infof logs a formatted info message
func (l *StandardLogger) Infof(format string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.mu.RLock()
		defer l.mu.RUnlock()
		msg := fmt.Sprintf(format, args...)
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logInfo.Print(msg)
	}
}

// Error logs an error message
func (l *StandardLogger) Error(msg string) {
	if l.level <= LogLevelError {
		l.mu.RLock()
		defer l.mu.RUnlock()
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logError.Print(msg)
	}
}

// Errorf logs a formatted error message
func (l *StandardLogger) Errorf(format string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.mu.RLock()
		defer l.mu.RUnlock()
		msg := fmt.Sprintf(format, args...)
		if len(l.fields) > 0 {
			msg = l.formatWithFields(msg)
		}
		l.logError.Print(msg)
	}
}

// Printf logs a formatted message at info level
func (l *StandardLogger) Printf(format string, args ...interface{}) {
	l.Infof(format, args...)
}

// Println logs a message at info level
func (l *StandardLogger) Println(args ...interface{}) {
	l.Info(fmt.Sprint(args...))
}

// Fatalf logs a formatted error message and exits the program
func (l *StandardLogger) Fatalf(format string, args ...interface{}) {
	l.Errorf(format, args...)
	panic(fmt.Sprintf(format, args...))
}

// WithField returns a new logger with an additional field
func (l *StandardLogger) WithField(key string, value interface{}) Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	newLogger := &StandardLogger{
		logError: l.logError,
		logInfo:  l.logInfo,
		logDebug: l.logDebug,
		fields:   make(map[string]interface{}, len(l.fields)+1),
		level:    l.level,
	}

	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	newLogger.fields[key] = value

	return newLogger
}

// WithFields returns a new logger with additional fields
func (l *StandardLogger) WithFields(fields map[string]interface{}) Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	newLogger := &StandardLogger{
		logError: l.logError,
		logInfo:  l.logInfo,
		logDebug: l.logDebug,
		fields:   make(map[string]interface{}, len(l.fields)+len(fields)),
		level:    l.level,
	}

	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// formatWithFields formats a message with structured fields
func (l *StandardLogger) formatWithFields(msg string) string {
	if len(l.fields) == 0 {
		return msg
	}

	fieldsStr := ""
	for k, v := range l.fields {
		if fieldsStr != "" {
			fieldsStr += " "
		}
		fieldsStr += fmt.Sprintf("%s=%v", k, v)
	}

	return fmt.Sprintf("%s [%s]", msg, fieldsStr)
}

// NoOpLogger is a logger that discards all output.
// It's useful for testing and for cases where logging should be disabled.
type NoOpLogger struct{}

// Debug discards the message
func (n *NoOpLogger) Debug(msg string) {}

// Debugf discards the formatted message
func (n *NoOpLogger) Debugf(format string, args ...interface{}) {}

// Info discards the message
func (n *NoOpLogger) Info(msg string) {}

// Infof discards the formatted message
func (n *NoOpLogger) Infof(format string, args ...interface{}) {}

// Error discards the message
func (n *NoOpLogger) Error(msg string) {}

// Errorf discards the formatted message
func (n *NoOpLogger) Errorf(format string, args ...interface{}) {}

// Printf discards the formatted message
func (n *NoOpLogger) Printf(format string, args ...interface{}) {}

// Println discards the message
func (n *NoOpLogger) Println(args ...interface{}) {}

// Fatalf discards the message and does not exit
func (n *NoOpLogger) Fatalf(format string, args ...interface{}) {}

// WithField returns the same NoOpLogger
func (n *NoOpLogger) WithField(key string, value interface{}) Logger {
	return n
}

// WithFields returns the same NoOpLogger
func (n *NoOpLogger) WithFields(fields map[string]interface{}) Logger {
	return n
}

var (
	// singletonNoOpLogger is the global instance of the no-op logger
	singletonNoOpLogger *NoOpLogger
	// noOpLoggerOnce ensures the singleton is created only once
	noOpLoggerOnce sync.Once
)

// GetNoOpLogger returns the singleton no-op logger instance.
// This reduces memory allocation by reusing the same no-op logger
// instance across the entire application.
func GetNoOpLogger() Logger {
	noOpLoggerOnce.Do(func() {
		singletonNoOpLogger = &NoOpLogger{}
	})
	return singletonNoOpLogger
}

// DefaultLogger creates a default logger based on the provided configuration
func DefaultLogger(level string) Logger {
	return NewStandardLogger(level, log.Writer(), log.Writer(), log.Writer())
}
