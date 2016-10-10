package bccsp

import (
	"testing"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

func TestDefaultBCCSP_GenKey(t *testing.T) {
	primitives.InitSecurityLevel("SHA2", 256)
	csp := &DefaultBCCSP{}

	k, err := csp.GenKey(&ECDSAGenKeyOpts{})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestEcdsaPrivateKey_PublicKey(t *testing.T) {
	primitives.InitSecurityLevel("SHA2", 256)
	csp := &DefaultBCCSP{}

	k, err := csp.GenKey(&ECDSAGenKeyOpts{})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private ECDSA key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestEcdsaPublicKey_ToByte(t *testing.T) {
	primitives.InitSecurityLevel("SHA2", 256)
	csp := &DefaultBCCSP{}

	k, err := csp.GenKey(&ECDSAGenKeyOpts{})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	raw, err := pk.ToByte()
	if err != nil {
		t.Fatalf("Failed marshalling ECDSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling ECDSA public key. Zero length")
	}
}

func TestDefaultBCCSP_Sign(t *testing.T) {
	primitives.InitSecurityLevel("SHA2", 256)
	csp := &DefaultBCCSP{}

	k, err := csp.GenKey(&ECDSAGenKeyOpts{})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")
	signature, err := csp.Sign(k, primitives.Hash(msg), nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}
}

func TestDefaultBCCSP_Verify(t *testing.T) {
	primitives.InitSecurityLevel("SHA2", 256)
	csp := &DefaultBCCSP{}

	k, err := csp.GenKey(&ECDSAGenKeyOpts{})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")
	signature, err := csp.Sign(k, primitives.Hash(msg), nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := csp.Verify(k, signature, primitives.Hash(msg))
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}