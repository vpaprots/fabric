package bccsp

import (
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"errors"
)

type aesPrivateKey struct {
	k []byte
	exportable bool
}


// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *aesPrivateKey) ToByte() (raw []byte, err error) {
	if k.exportable {
		return k.k, nil
	}

	return nil, errors.New("Not supported.")
}

// GetSKI returns the subject key identifier of this key.
func (k *aesPrivateKey) GetSKI() (ski []byte) {
	return primitives.Hash(k.k)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *aesPrivateKey) Symmetric() (bool) {
	return true
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *aesPrivateKey) Private() (bool) {
	return true
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *aesPrivateKey) PublicKey() (Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}