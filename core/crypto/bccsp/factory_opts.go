package bccsp

type GenericFactoryOpts struct {
	ProviderName  string
	EphemeralFlag bool
}

// Provider returns the name of the provider
func (o *GenericFactoryOpts) FactoryName() string {
	return o.ProviderName
}

// Ephemeral returns true if the CSP has to be ephemeral, false otherwise
func (o *GenericFactoryOpts) Ephemeral() bool {
	return o.EphemeralFlag
}

type SwFactoryOpts struct {
	EphemeralFlag bool
}

// Provider returns the name of the provider
func (o *SwFactoryOpts) FactoryName() string {
	return SOFTWARE_BASED_FACTORY_NAME
}

// Ephemeral returns true if the CSP has to be ephemeral, false otherwise
func (o *SwFactoryOpts) Ephemeral() bool {
	return o.EphemeralFlag
}
