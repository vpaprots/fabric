package bccsp

type ECDSAGenKeyOpts struct {
	Temporary bool
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *ECDSAGenKeyOpts) Algorithm() string {
	return "ECDSA"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAGenKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

type ECDSAReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *ECDSAReRandKeyOpts) Algorithm() string {
	return "ECDSA_RERAND"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *ECDSAReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}
