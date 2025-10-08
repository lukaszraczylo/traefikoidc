package traefikoidc

import (
	"io"
	"log"
	"sync"
)

var (
	// singletonNoOpLogger is the global instance of the no-op logger
	singletonNoOpLogger *Logger
	// noOpLoggerOnce ensures the singleton is created only once
	noOpLoggerOnce sync.Once
	// noOpLoggerMu protects access to the singleton logger during reset
	noOpLoggerMu sync.RWMutex
)

// GetSingletonNoOpLogger returns the singleton no-op logger instance.
// This reduces memory allocation by reusing the same no-op logger
// instance across the entire application.
func GetSingletonNoOpLogger() *Logger {
	noOpLoggerMu.RLock()
	if singletonNoOpLogger != nil {
		logger := singletonNoOpLogger
		noOpLoggerMu.RUnlock()
		return logger
	}
	noOpLoggerMu.RUnlock()

	noOpLoggerMu.Lock()
	defer noOpLoggerMu.Unlock()

	// Double-check after acquiring write lock
	if singletonNoOpLogger != nil {
		return singletonNoOpLogger
	}

	noOpLoggerOnce.Do(func() {
		singletonNoOpLogger = &Logger{
			logError: log.New(io.Discard, "", 0),
			logInfo:  log.New(io.Discard, "", 0),
			logDebug: log.New(io.Discard, "", 0),
		}
	})
	return singletonNoOpLogger
}

// ResetSingletonNoOpLogger resets the singleton instance (mainly for testing)
func ResetSingletonNoOpLogger() {
	noOpLoggerMu.Lock()
	defer noOpLoggerMu.Unlock()

	noOpLoggerOnce = sync.Once{}
	singletonNoOpLogger = nil
}
