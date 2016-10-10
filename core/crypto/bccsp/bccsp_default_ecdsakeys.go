package bccsp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

type ecdsaPrivateKey struct {
	k *ecdsa.PrivateKey
}


// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *ecdsaPrivateKey) ToByte() (raw []byte, err error) {
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *ecdsaPrivateKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PrivateKeyToDER(k.k)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *ecdsaPrivateKey) Symmetric() (bool) {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *ecdsaPrivateKey) Private() (bool) {
	return true
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *ecdsaPrivateKey) PublicKey() (Key, error) {
	return &ecdsaPublicKey{&k.k.PublicKey}, nil
}


type ecdsaPublicKey struct {
	k *ecdsa.PublicKey
}


// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *ecdsaPublicKey) ToByte() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.k)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *ecdsaPublicKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PublicKeyToPEM(k.k, nil)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *ecdsaPublicKey) Symmetric() (bool) {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *ecdsaPublicKey) Private() (bool) {
	return false
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *ecdsaPublicKey) PublicKey() (Key, error) {
	return k, nil
}

