package bccsp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/miekg/pkcs11"
)

type h11ECDSAPrivateKey struct {
	k *ecdsa.PrivateKey
	privateP11Key pkcs11.ObjectHandle
	pubicP11Key pkcs11.ObjectHandle
	tokenLabel string
}

// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *h11ECDSAPrivateKey) Bytes() (raw []byte, err error) {
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *h11ECDSAPrivateKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PrivateKeyToDER(k.k)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
	// return k.tokenLabel
}

// <VP> GetSKI returns the subject key identifier of this key.
func (k *h11ECDSAPrivateKey) GetSKI2() (ski []byte) {
	return []byte("VT")
//	return k.tokenLabel.Bytes()
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *h11ECDSAPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *h11ECDSAPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *h11ECDSAPrivateKey) PublicKey() (Key, error) {
	return &h11ECDSAPublicKey{&k.k.PublicKey, k.pubicP11Key}, nil
}

type h11ECDSAPublicKey struct {
	k *ecdsa.PublicKey
	pubicP11Key pkcs11.ObjectHandle
}

// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *h11ECDSAPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.k)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *h11ECDSAPublicKey) GetSKI() (ski []byte) {
	raw, _ := primitives.PublicKeyToPEM(k.k, nil)
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return primitives.Hash(raw)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *h11ECDSAPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *h11ECDSAPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *h11ECDSAPublicKey) PublicKey() (Key, error) {
	return k, nil
}
