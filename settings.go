package traefikoidc

import (
	"fmt"
	"net/http"
	"os"
)

const (
	cookieName = "_raczylo_oidc"
)

type Config struct {
	ProviderURL          string   `json:"providerURL"`
	CallbackURL          string   `json:"callbackURL"`
	LogoutURL            string   `json:"logoutURL"`
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	Scopes               []string `json:"scopes"`
	LogLevel             string   `json:"logLevel"`
	SessionEncryptionKey string   `json:"sessionEncryptionKey"`
	ForceHTTPS           bool     `json:"forceHTTPS"`
}

func CreateConfig() *Config {
	c := &Config{
		Scopes:   []string{"openid", "profile", "email"},
		LogLevel: "info",
	}

	if c.LogoutURL == "" {
		c.LogoutURL = c.CallbackURL + "/logout"
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

type defaultLogger struct {
	level string
}

func NewLogger(level string) Logger {
	return &defaultLogger{level: level}
}

func (l *defaultLogger) Info(args ...interface{}) {
	if l.level == "info" || l.level == "debug" {
		fmt.Println(append([]interface{}{"INFO:"}, args...)...)
	}
}

func (l *defaultLogger) Infof(format string, args ...interface{}) {
	if l.level == "info" || l.level == "debug" {
		fmt.Printf("INFO: "+format+"\n", args...)
	}
}

func (l *defaultLogger) Error(args ...interface{}) {
	fmt.Fprintln(os.Stderr, append([]interface{}{"ERROR:"}, args...)...)
}

func (l *defaultLogger) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

type HTTPClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

func handleError(w http.ResponseWriter, message string, code int, logger Logger) {
	logger.Errorf(message)
	http.Error(w, message, code)
}
