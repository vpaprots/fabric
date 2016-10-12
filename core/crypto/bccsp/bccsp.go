package bccsp

import "crypto"

// Key represents a key
type Key interface {

	// ToByte converts this key to its byte representation,
	// if this operation is allowed.
	ToByte() ([]byte, error)

	// GetSKI returns the subject key identifier of this key.
	GetSKI() []byte

	// Symmetric returns true if this key is a symmetric key,
	// false is this key is asymmetric
	Symmetric() (bool)

	// Private returns true if this key is an asymmetric private key,
	// false otherwise.
	Private() (bool)

	// PublicKey returns the corresponding public key if this key
	// is an asymmetric private key. If this key is already public,
	// PublicKey returns this key itself.
	PublicKey() (Key, error)
}

// GenKeyOpts contains options for key-generation with a CSP.
type GenKeyOpts interface {

	// Algorithm returns an identifier for the algorithm to be used
	// to generate a key.
	Algorithm() string

	// Ephemeral returns true if the key to generate has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// DeriveKeyOpts contains options for key-derivation with a CSP.
type DeriveKeyOpts interface {

	// Algorithm returns an identifier for the algorithm to be used
	// to derive a key.
	Algorithm() string

	// Ephemeral returns true if the key to derived has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// ImportKeyOpts contains options for importing the raw material of a key with a CSP.
type ImportKeyOpts interface{
	// Algorithm returns an identifier for the algorithm to be used
	// to import the raw material of a key.
	Algorithm() string

	// Ephemeral returns true if the key generated has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// SignerOpts contains options for signing with a CSP.
type SignerOpts interface{
	crypto.SignerOpts
}

// EncrypterOpts contains options for encrypting with a CSP.
type EncrypterOpts interface{}

// DecrypterOpts contains options for decrypting with a CSP.
type DecrypterOpts interface{}

// CSPFactoryOpts contains options for instantiating CSPs.
type CSPFactoryOpts interface {

	// Provider returns the name of the provider
	Provider() string

	// Ephemeral returns true if the CSP has to be ephemeral, false otherwise
	Ephemeral() bool

	// Hardware returns true if the CSP has hardware-based, false otherwise
	Hardware() bool
}

// BCCSP is the blockchain cryptographic service provider that offers
// the implementation of cryptographic standards and algorithms.
type BCCSP interface {

	// GenKey generates a key using opts.
	GenKey(opts GenKeyOpts) (k Key, err error)

	// DeriveKey derives a key from k using opts.
	// The opts argument should be appropriate for the primitive used.
	DeriveKey(k Key, opts DeriveKeyOpts) (dk Key, err error)

	// GetKey returns the key this CSP associates to
	// the Subject Key Identifier ski.
	GetKey(ski []byte) (k Key, err error)

	// ImportKey imports a key from its raw representation using opts.
	// The opts argument should be appropriate for the primitive used.
	ImportKey(raw []byte, opts ImportKeyOpts) (k Key, err error)

	// Sign signs digest using key k.
	// The opts argument should be appropriate for the primitive used.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest).
	Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error)

	// Verify verifies signature against key k and digest
	Verify(k Key, signature, digest []byte) (valid bool, err error)

	// Encrypt encrypts plaintext using key k.
	// The opts argument should be appropriate for the primitive used.
	Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error)

	// Decrypt decrypts ciphertext using key k.
	// The opts argument should be appropriate for the primitive used.
	Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error)
}
