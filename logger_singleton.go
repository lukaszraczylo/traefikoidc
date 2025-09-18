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
)

// GetSingletonNoOpLogger returns the singleton no-op logger instance.
// This reduces memory allocation by reusing the same no-op logger
// instance across the entire application.
func GetSingletonNoOpLogger() *Logger {
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
	noOpLoggerOnce = sync.Once{}
	singletonNoOpLogger = nil
}
