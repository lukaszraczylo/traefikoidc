package traefikoidc

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
	return &Config{}
}
