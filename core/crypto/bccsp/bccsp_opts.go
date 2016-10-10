package bccsp

type ECDSAGenKeyOpts struct {
	ephemeral bool
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *ECDSAGenKeyOpts) Algorithm() string {
	return "ECDSA"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAGenKeyOpts) Ephemeral() bool {
	return opts.ephemeral
}
