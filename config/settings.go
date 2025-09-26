// Package config provides configuration management for the OIDC middleware
package config

import (
	"net/http"
)

const (
	minEncryptionKeyLength = 16
	ConstSessionTimeout    = 86400
)

//lint:ignore U1000 May be referenced for default exclusion patterns
var defaultExcludedURLs = map[string]struct{}{
	"/favicon.ico":  {},
	"/robots.txt":   {},
	"/health":       {},
	"/.well-known/": {},
	"/metrics":      {},
	"/ping":         {},
	"/api/":         {},
	"/static/":      {},
	"/assets/":      {},
	"/js/":          {},
	"/css/":         {},
	"/images/":      {},
	"/fonts/":       {},
}

// Settings manages configuration and initialization for the OIDC middleware
type Settings struct {
	logger Logger
}

// Logger interface for dependency injection
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// Config represents the configuration for the OIDC middleware
type Config struct {
	ProviderURL               string         `json:"providerUrl"`
	ClientID                  string         `json:"clientId"`
	ClientSecret              string         `json:"clientSecret"`
	CallbackURL               string         `json:"callbackUrl"`
	LogoutURL                 string         `json:"logoutUrl"`
	PostLogoutRedirectURI     string         `json:"postLogoutRedirectUri"`
	SessionEncryptionKey      string         `json:"sessionEncryptionKey"`
	ForceHTTPS                bool           `json:"forceHttps"`
	LogLevel                  string         `json:"logLevel"`
	Scopes                    []string       `json:"scopes"`
	OverrideScopes            bool           `json:"overrideScopes"`
	AllowedUsers              []string       `json:"allowedUsers"`
	AllowedUserDomains        []string       `json:"allowedUserDomains"`
	AllowedRolesAndGroups     []string       `json:"allowedRolesAndGroups"`
	ExcludedURLs              []string       `json:"excludedUrls"`
	EnablePKCE                bool           `json:"enablePkce"`
	RateLimit                 int            `json:"rateLimit"`
	RefreshGracePeriodSeconds int            `json:"refreshGracePeriodSeconds"`
	Headers                   []HeaderConfig `json:"headers"`
	HTTPClient                *http.Client   `json:"-"`
	CookieDomain              string         `json:"cookieDomain"`
}

// HeaderConfig represents header template configuration
type HeaderConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NewSettings creates a new Settings instance
func NewSettings(logger Logger) *Settings {
	return &Settings{
		logger: logger,
	}
}

// CreateConfig creates a default configuration
func CreateConfig() *Config {
	return &Config{
		LogLevel:                  "INFO",
		ForceHTTPS:                true,
		EnablePKCE:                true,
		RateLimit:                 10,
		RefreshGracePeriodSeconds: 60,
		Scopes:                    []string{"openid", "profile", "email"},
		Headers:                   []HeaderConfig{},
	}
}
