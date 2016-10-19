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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{false})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{false})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling ECDSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling ECDSA public key. Zero length")
	}
}

func TestEcdsaPublicKey_GetSKI(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	reRandomizedKey, err := csp.KeyDeriv(k, &ECDSAReRandKeyOpts{false, []byte{1}})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{true})
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

	k, err := csp.KeyGen(&ECDSAGenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	reRandomizedKey, err := csp.KeyDeriv(k, &ECDSAReRandKeyOpts{false, []byte{1}})
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

func TestDefaultBCCSP_GenKey3(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES_256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES_256 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES_256 key. Key should be symmetric")
	}
}

func TestDefaultBCCSP_Encrypt(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	ct, err := csp.Encrypt(k, []byte("Hello World"), &AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed encrypting. Nil ciphertext")
	}
}

func TestDefaultBCCSP_Decrypt(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	msg := []byte("Hello World")

	ct, err := csp.Encrypt(k, msg, &AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := csp.Decrypt(k, ct, AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestDefaultBCCSP_DeriveKey3(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	hmcaedKey, err := csp.KeyDeriv(k, &HMACTruncated256AESDeriveKeyOpts{false, []byte{1}})
	if err != nil {
		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
	}
	if !hmcaedKey.Private() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
	}
	if !hmcaedKey.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
	}
	raw, err := hmcaedKey.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Operation must be forbidden")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Operation must return 0 bytes")
	}


	msg := []byte("Hello World")

	ct, err := csp.Encrypt(hmcaedKey, msg, &AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := csp.Decrypt(hmcaedKey, ct, AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}

}

func TestDefaultBCCSP_DeriveKey4(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	hmcaedKey, err := csp.KeyDeriv(k, &HMACDeriveKeyOpts{false, []byte{1}})

	if err != nil {
		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
	}
	if !hmcaedKey.Private() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
	}
	if !hmcaedKey.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
	}
	raw, err := hmcaedKey.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling to bytes [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling to bytes. 0 bytes")
	}
}

func TestDefaultBCCSP_ImportKey(t *testing.T) {
	csp := getDefaultBCCSP(t)

	raw, err := primitives.GenAESKey()
	if err != nil {
		t.Fatalf("Failed generating AES key [%s]", err)
	}

	k, err := csp.KeyImport(raw, &AES256ImportKeyOpts{true})
	if err != nil {
		t.Fatalf("Failed importing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed importing AES_256 key. Imported Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed HMACing AES_256 key. Imported Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. Imported Key should be asymmetric")
	}
	raw, err = k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := csp.Encrypt(k, msg, &AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := csp.Decrypt(k, ct, AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}

}

func TestDefaultBCCSP_ImportKey2(t *testing.T) {
	csp := getDefaultBCCSP(t)

	_, err := csp.KeyImport(nil, &AES256ImportKeyOpts{true})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing nil key")
	}

	_, err = csp.KeyImport([]byte{1}, &AES256ImportKeyOpts{true})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing a key with an invalid length")
	}
}

func TestDefaultBCCSP_GetKey2(t *testing.T) {
	csp := getDefaultBCCSP(t)

	k, err := csp.KeyGen(&AES256GenKeyOpts{false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	k2, err := csp.GetKey(k.GetSKI())
	if err != nil {
		t.Fatalf("Failed getting AES_256 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting AES_256 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting AES_256 key. Key should be private")
	}
	if !k2.Symmetric() {
		t.Fatal("Failed getting AES_256 key. Key should be symmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.GetSKI(), k2.GetSKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.GetSKI(), k2.GetSKI())
	}

}