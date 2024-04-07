package traefikoidc

import "os"

// constants
const (
	cookie_name = "_raczylo_oidc"
)

type Config struct {
	ProviderURL          string   `json:"providerURL"`
	CallbackURL          string   `json:"callbackURL"`
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	Scopes               []string `json:"scopes"`
	LogLevel             string   `json:"logLevel"`
	SessionEncryptionKey string   `json:"sessionEncryptionKey"`
}

func CreateConfig() *Config {
	infoLogger.SetOutput(os.Stdout)
	return &Config{}
}
