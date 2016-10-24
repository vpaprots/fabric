package bccsp

//import (
//	"crypto/ecdsa"
//	"crypto/x509"
//	"fmt"

//	"github.com/hyperledger/fabric/core/crypto/primitives"
//	"github.com/miekg/pkcs11"
//)

// SKIs are filled during object creation etc., outside go

type p11ECDSAPrivateKey struct {
//	k *ecdsa.PrivateKey
//	privateP11Key pkcs11.ObjectHandle
//	pubicP11Key pkcs11.ObjectHandle
	pub *p11ECDSAPublicKey
	label string
	ski []byte
}

// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *p11ECDSAPrivateKey) Bytes() (raw []byte, err error) {
	return
}

// GetSKI returns the subject key identifier of this key.
func (k *p11ECDSAPrivateKey) GetSKI() (ski []byte) {
	// TODO: Error should not be thrown. Anyway, move the marshalling at initialization.

	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *p11ECDSAPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *p11ECDSAPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *p11ECDSAPrivateKey) PublicKey() (Key, error) {
	return &p11ECDSAPublicKey{k.pub.spki, k.pub.label, k.pub.ski}, nil
}

type p11ECDSAPublicKey struct {
	spki []byte
	label string
	ski []byte
}

// ToByte converts this key to its byte representation,
// if this operation is allowed.
func (k *p11ECDSAPublicKey) Bytes() (raw []byte, err error) {
	return k.spki, nil
}

// GetSKI returns the subject key identifier of this key.
func (k *p11ECDSAPublicKey) GetSKI() (ski []byte) {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *p11ECDSAPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is an asymmetric private key,
// false otherwise.
func (k *p11ECDSAPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key if this key
// is an asymmetric private key. If this key is already public,
// PublicKey returns this key itself.
func (k *p11ECDSAPublicKey) PublicKey() (Key, error) {
	return k, nil
}
