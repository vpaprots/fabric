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

type AES256GenKeyOpts struct {
	Temporary bool
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *AES256GenKeyOpts) Algorithm() string {
	return "AES_256"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *AES256GenKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

type AESCBCPKCS7ModeOpts struct {

}

type HMACTruncated256AESDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *HMACTruncated256AESDeriveKeyOpts) Algorithm() string {
	return "HMAC_TRUNCATED_256"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256AESDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256AESDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

type HMACDeriveKeyOpts struct {
	Temporary bool
	Arg []byte
}

// Algorithm returns an identifier for the algorithm to be used
// to generate a key.
func (opts *HMACDeriveKeyOpts) Algorithm() string {
	return "HMAC"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}
