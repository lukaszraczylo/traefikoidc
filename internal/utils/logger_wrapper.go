package utils

import (
	"github.com/lukaszraczylo/traefikoidc/internal/cleanup"
	"github.com/lukaszraczylo/traefikoidc/internal/recovery"
)

// LoggerInterface defines the common logger interface used across the package
type LoggerInterface interface {
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ============================================================================
// RECOVERY LOGGER WRAPPER
// ============================================================================

// recoveryLoggerWrapper wraps a logger to match recovery.Logger interface
type recoveryLoggerWrapper struct {
	logger LoggerInterface
}

// WrapLoggerForRecovery wraps a logger for use with recovery modules
func WrapLoggerForRecovery(logger LoggerInterface) recovery.Logger {
	return &recoveryLoggerWrapper{logger: logger}
}

// Logf logs an informational message
func (lw *recoveryLoggerWrapper) Logf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Infof(format, args...)
	}
}

// ErrorLogf logs an error message
func (lw *recoveryLoggerWrapper) ErrorLogf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Errorf(format, args...)
	}
}

// DebugLogf logs a debug message
func (lw *recoveryLoggerWrapper) DebugLogf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Debugf(format, args...)
	}
}

// ============================================================================
// CLEANUP LOGGER WRAPPER
// ============================================================================

// cleanupLoggerWrapper wraps a logger to match cleanup.Logger interface
type cleanupLoggerWrapper struct {
	logger LoggerInterface
}

// WrapLoggerForCleanup wraps a logger for use with cleanup modules
func WrapLoggerForCleanup(logger LoggerInterface) cleanup.Logger {
	return &cleanupLoggerWrapper{logger: logger}
}

// Logf logs an informational message
func (lw *cleanupLoggerWrapper) Logf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Infof(format, args...)
	}
}

// ErrorLogf logs an error message
func (lw *cleanupLoggerWrapper) ErrorLogf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Errorf(format, args...)
	}
}

// DebugLogf logs a debug message
func (lw *cleanupLoggerWrapper) DebugLogf(format string, args ...interface{}) {
	if lw.logger != nil {
		lw.logger.Debugf(format, args...)
	}
}

// ============================================================================
// SESSION LOGGER WRAPPER
// ============================================================================

// Note: Session logger wrapper is not included here because session.Logger
// has a different interface (Debug/Info/Warn/Error instead of Logf/ErrorLogf/DebugLogf).
// Each package should implement its own session logger adapter as needed.
