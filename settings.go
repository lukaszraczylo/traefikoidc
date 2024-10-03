package traefikoidc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

const (
	cookieName = "_raczylo_oidc"
)

type Config struct {
	ProviderURL          string   `json:"providerURL"`
	RevocationURL        string   `json:"revocationURL"`
	CallbackURL          string   `json:"callbackURL"`
	LogoutURL            string   `json:"logoutURL"`
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	Scopes               []string `json:"scopes"`
	LogLevel             string   `json:"logLevel"`
	SessionEncryptionKey string   `json:"sessionEncryptionKey"`
	ForceHTTPS           bool     `json:"forceHTTPS"`
	RateLimit            int      `json:"rateLimit"`
	ExcludedURLs         []string `json:"excludedURLs"`
	AllowedUserDomains   []string `json:"allowedUserDomains"`
	HTTPClient           *http.Client
}

var defaultSessionOptions = &sessions.Options{
	HttpOnly: true,
	Secure:   false,
	SameSite: http.SameSiteLaxMode,
	MaxAge:   ConstSessionTimeout,
	Path:     "/",
}

func CreateConfig() *Config {
	c := &Config{}

	if c.Scopes == nil {
		c.Scopes = []string{"openid", "profile", "email"}
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if c.LogoutURL == "" {
		c.LogoutURL = c.CallbackURL + "/logout"
	}

	if c.RateLimit == 0 {
		c.RateLimit = 100
	}

	return c
}

func (c *Config) Validate() error {
	if c.ProviderURL == "" {
		return fmt.Errorf("providerURL is required")
	}
	if c.CallbackURL == "" {
		return fmt.Errorf("callbackURL is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}
	if c.SessionEncryptionKey == "" {
		return fmt.Errorf("sessionEncryptionKey is required")
	}
	return nil
}

type Logger struct {
	logError *log.Logger
	logInfo  *log.Logger
	logDebug *log.Logger
}

func NewLogger(logLevel string) *Logger {
	logError := log.New(io.Discard, "ERROR: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: TraefikOidcPlugin: ", log.Ldate|log.Ltime)

	logError.SetOutput(os.Stderr)
	logInfo.SetOutput(os.Stdout)

	if logLevel == "debug" {
		logDebug.SetOutput(os.Stdout)
	}

	return &Logger{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error(message)
	http.Error(w, message, code)
}
