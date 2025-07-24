package providers

// GenericProvider encapsulates standard OIDC logic for any compliant provider.
type GenericProvider struct {
	*BaseProvider
}

// NewGenericProvider creates a new instance of the GenericProvider.
func NewGenericProvider() *GenericProvider {
	return &GenericProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *GenericProvider) GetType() ProviderType {
	return ProviderTypeGeneric
}
