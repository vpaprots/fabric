package bccsp

import (
	"crypto/rand"
	"testing"

	"github.com/hyperledger/fabric/core/crypto/primitives"
)

func TestCryptoSigner_Init(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	signer := &CryptoSigner{}
	err = signer.Init(csp, k)
	if err != nil {
		t.Fatalf("Failed initializing CryptoSigner [%s]", err)
	}
}

func TestCryptoSigner_Public(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	signer := &CryptoSigner{}
	err = signer.Init(csp, k)
	if err != nil {
		t.Fatalf("Failed initializing CryptoSigner [%s]", err)
	}

	pk := signer.Public()
	if pk == nil {
		t.Fatal("Failed getting PublicKey. Nil.")
	}
}

func TestCryptoSigner_Sign(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	signer := &CryptoSigner{}
	err = signer.Init(csp, k)
	if err != nil {
		t.Fatalf("Failed initializing CryptoSigner [%s]", err)
	}

	msg := []byte("Hello World")
	signature, err := signer.Sign(rand.Reader, primitives.Hash(msg), nil)
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
