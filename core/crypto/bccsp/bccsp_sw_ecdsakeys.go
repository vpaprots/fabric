package bccsp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

type swECDSAPrivateKey struct {
	k *ecdsa.PrivateKey
}


// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *swECDSAPrivateKey) Bytes() (raw []byte, err error) {
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *swECDSAPrivateKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PrivateKeyToDER(k.k)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *swECDSAPrivateKey) Symmetric() (bool) {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *swECDSAPrivateKey) Private() (bool) {
	return true
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *swECDSAPrivateKey) PublicKey() (Key, error) {
	return &swECDSAPublicKey{&k.k.PublicKey}, nil
}


type swECDSAPublicKey struct {
	k *ecdsa.PublicKey
}


// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *swECDSAPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.k)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *swECDSAPublicKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PublicKeyToPEM(k.k, nil)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *swECDSAPublicKey) Symmetric() (bool) {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *swECDSAPublicKey) Private() (bool) {
	return false
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *swECDSAPublicKey) PublicKey() (Key, error) {
	return k, nil
}

