package bccsp

import (
	"testing"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/spf13/viper"
	"os"
	"bytes"
)

func getDefaultBCCSP(t *testing.T) BCCSP {
	primitives.InitSecurityLevel("SHA2", 256)
	viper.Set("security.bccsp.default.keyStorePath", os.TempDir())
	csp, err := GetDefault()
	if err != nil {
		t.Fatalf("Failed getting Default CSP [%s]", err)
	}

	return csp
}

func TestDefaultBCCSP_GenKey(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
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

func TestEcdsaPrivateKey_GetSKI(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	ski := k.GetSKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestDefaultBCCSP_GenKey2(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{false})
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

func TestDefaultBCCSP_GetKey(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	k2, err := csp.GetKey(k.GetSKI())
	if err != nil {
		t.Fatalf("Failed getting ECDSA key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting ECDSA key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting ECDSA key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting ECDSA key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.GetSKI(), k2.GetSKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.GetSKI(), k2.GetSKI())
	}
}

func TestEcdsaPrivateKey_PublicKey(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
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
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
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

func TestEcdsaPublicKey_GetSKI(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	ski := pk.GetSKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestDefaultBCCSP_DeriveKey(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	reRandomizedKey, err := csp.DeriveKey(k, &ECDSAReRandKeyOpts{false, []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key must be different from nil")
	}
	if !reRandomizedKey.Private() {
		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key should be private")
	}
	if reRandomizedKey.Symmetric() {
		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key should be asymmetric")
	}
}

func TestDefaultBCCSP_Sign(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
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
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{true})
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

func TestDefaultBCCSP_DeriveKey2(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.GenKey(&ECDSAGenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	reRandomizedKey, err := csp.DeriveKey(k, &ECDSAReRandKeyOpts{false, []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")
	signature, err := csp.Sign(reRandomizedKey, primitives.Hash(msg), nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := csp.Verify(reRandomizedKey, signature, primitives.Hash(msg))
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}