package logger

import (
	"io"
	"os"
	"sync"
)

// Factory creates and manages logger instances with singleton support
// for common logger types to reduce memory allocation.
type Factory struct {
	mu              sync.RWMutex
	defaultLogger   Logger
	noOpLogger      Logger
	loggers         map[string]Logger
	defaultLogLevel string
}

var (
	// globalFactory is the singleton factory instance
	globalFactory *Factory
	// factoryOnce ensures the factory is created only once
	factoryOnce sync.Once
)

// GetFactory returns the global logger factory instance
func GetFactory() *Factory {
	factoryOnce.Do(func() {
		globalFactory = &Factory{
			loggers:         make(map[string]Logger),
			defaultLogLevel: "info",
		}
	})
	return globalFactory
}

// SetDefaultLogLevel sets the default log level for new loggers
func (f *Factory) SetDefaultLogLevel(level string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaultLogLevel = level
}

// GetLogger returns a logger for the given name, creating one if it doesn't exist
func (f *Factory) GetLogger(name string) Logger {
	f.mu.RLock()
	if logger, exists := f.loggers[name]; exists {
		f.mu.RUnlock()
		return logger
	}
	f.mu.RUnlock()

	// Create new logger
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double check after acquiring write lock
	if logger, exists := f.loggers[name]; exists {
		return logger
	}

	logger := f.createLogger(name)
	f.loggers[name] = logger
	return logger
}

// createLogger creates a new logger instance
func (f *Factory) createLogger(name string) Logger {
	if name == "noop" || name == "no-op" || name == "discard" {
		return GetNoOpLogger()
	}

	// Create logger with appropriate outputs based on environment
	var errorOut, infoOut, debugOut io.Writer

	if os.Getenv("OIDC_LOG_TO_FILE") == "true" {
		// Log to files if configured
		errorOut = getOrCreateLogFile("error.log")
		infoOut = getOrCreateLogFile("info.log")
		debugOut = getOrCreateLogFile("debug.log")
	} else {
		// Default to stdout/stderr
		errorOut = os.Stderr
		infoOut = os.Stdout
		debugOut = os.Stdout
	}

	return NewStandardLogger(f.defaultLogLevel, errorOut, infoOut, debugOut)
}

// GetDefaultLogger returns the default logger instance
func (f *Factory) GetDefaultLogger() Logger {
	f.mu.RLock()
	if f.defaultLogger != nil {
		f.mu.RUnlock()
		return f.defaultLogger
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.defaultLogger == nil {
		f.defaultLogger = f.createLogger("default")
	}

	return f.defaultLogger
}

// GetNoOpLogger returns the singleton no-op logger
func (f *Factory) GetNoOpLogger() Logger {
	f.mu.RLock()
	if f.noOpLogger != nil {
		f.mu.RUnlock()
		return f.noOpLogger
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.noOpLogger == nil {
		f.noOpLogger = GetNoOpLogger()
	}

	return f.noOpLogger
}

// Clear removes all cached loggers (useful for testing)
func (f *Factory) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.loggers = make(map[string]Logger)
	f.defaultLogger = nil
	// Don't clear noOpLogger as it's a singleton
}

// getOrCreateLogFile returns a file writer for the given log file
func getOrCreateLogFile(filename string) io.Writer {
	logDir := os.Getenv("OIDC_LOG_DIR")
	if logDir == "" {
		logDir = "/var/log/traefik-oidc"
	}

	// Ensure log directory exists
	// #nosec G301 -- log directory needs to be readable by monitoring tools
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// Fall back to stderr if we can't create the directory
		return os.Stderr
	}

	filepath := logDir + "/" + filename
	// #nosec G302 G304 -- log files need to be readable; path is from trusted env var
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fall back to stderr if we can't open the file
		return os.Stderr
	}

	return file
}

// Global convenience functions

// New creates a new logger with the specified level
func New(level string) Logger {
	return GetFactory().GetLogger(level)
}

// Default returns the default logger
func Default() Logger {
	return GetFactory().GetDefaultLogger()
}

// NoOp returns a no-op logger
func NoOp() Logger {
	return GetFactory().GetNoOpLogger()
}

// WithLevel creates a new logger with the specified level
func WithLevel(level string) Logger {
	return NewStandardLogger(level, os.Stderr, os.Stdout, os.Stdout)
}
