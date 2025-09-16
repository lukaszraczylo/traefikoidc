package logger

import (
	"fmt"
	"log"
)

// LegacyLoggerAdapter wraps the old Logger struct from the main package
// to implement the new unified Logger interface. This allows for gradual
// migration of the codebase to the new logger interface.
type LegacyLoggerAdapter struct {
	logError *log.Logger
	logInfo  *log.Logger
	logDebug *log.Logger
}

// NewLegacyAdapter creates a new adapter from the old logger components
func NewLegacyAdapter(logError, logInfo, logDebug *log.Logger) Logger {
	if logError == nil || logInfo == nil || logDebug == nil {
		return GetNoOpLogger()
	}
	return &LegacyLoggerAdapter{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

// Debug logs a debug message
func (l *LegacyLoggerAdapter) Debug(msg string) {
	l.logDebug.Print(msg)
}

// Debugf logs a formatted debug message
func (l *LegacyLoggerAdapter) Debugf(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Info logs an info message
func (l *LegacyLoggerAdapter) Info(msg string) {
	l.logInfo.Print(msg)
}

// Infof logs a formatted info message
func (l *LegacyLoggerAdapter) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Error logs an error message
func (l *LegacyLoggerAdapter) Error(msg string) {
	l.logError.Print(msg)
}

// Errorf logs a formatted error message
func (l *LegacyLoggerAdapter) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// Printf logs a formatted message at info level
func (l *LegacyLoggerAdapter) Printf(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Println logs a message at info level
func (l *LegacyLoggerAdapter) Println(args ...interface{}) {
	l.logInfo.Print(args...)
}

// Fatalf logs a formatted error message and panics
func (l *LegacyLoggerAdapter) Fatalf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
	panic(fmt.Sprintf(format, args...))
}

// WithField returns the same logger (no structured logging support in legacy adapter)
func (l *LegacyLoggerAdapter) WithField(key string, value interface{}) Logger {
	return l
}

// WithFields returns the same logger (no structured logging support in legacy adapter)
func (l *LegacyLoggerAdapter) WithFields(fields map[string]interface{}) Logger {
	return l
}
