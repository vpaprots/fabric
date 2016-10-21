package bccsp

import (
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"fmt"
	"errors"
	"crypto/rand"
	"crypto/ecdsa"
	"encoding/asn1"
	"github.com/op/go-logging"
	"encoding/hex"
	"math/big"
	"github.com/hyperledger/fabric/core/crypto/utils"
)

var (
	p11BCCSPLog = logging.MustGetLogger("bccsp_default")
)



// P11BCCSP is the PKCS11-based implementation of the BCCSP.
// It is based on code used in the primitives package.
// It can be configured via vipe.
type P11BCCSP struct {
	ks *swBCCSPKeyStore
}

// KeyGen generates a key using opts.
func (csp *P11BCCSP) KeyGen(opts KeyGenOpts) (k Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid argument. Nil.")
	}

	// Parse algorithm
	switch opts.Algorithm() {
	case "ECDSA":
		lowLevelKey, err := primitives.NewECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA key [%s]", err)
		}

		k = &swECDSAPrivateKey{lowLevelKey}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storePrivateKey(hex.EncodeToString(k.GetSKI()), lowLevelKey)
			if err != nil {
				return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
			}
		}

		return k, nil
	case "AES_256":
		lowLevelKey, err := primitives.GenAESKey()

		if err != nil {
			return nil, fmt.Errorf("Failed generating AES_256 key [%s]", err)
		}

		k = &swAESPrivateKey{lowLevelKey, false}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storeKey(hex.EncodeToString(k.GetSKI()), lowLevelKey)
			if err != nil {
				return nil, fmt.Errorf("Failed storing AES_256 key [%s]", err)
			}
		}

		return k, nil
	default:
		return nil, fmt.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
	}
	// return // no other options available [linter]
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *P11BCCSP) KeyDeriv(k Key, opts KeyDerivOpts) (dk Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Derive key
	switch k.(type) {
	case *swECDSAPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		ecdsaK := k.(*swECDSAPrivateKey)

		switch opts.(type) {

		// Re-randomized an ECDSA private key
		case *ECDSAReRandKeyOpts:
			reRandOpts := opts.(*ECDSAReRandKeyOpts)
			tempSK := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: ecdsaK.k.Curve,
					X:     new(big.Int),
					Y:     new(big.Int),
				},
				D: new(big.Int),
			}

			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(ecdsaK.k.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			tempSK.D.Add(ecdsaK.k.D, k)
			tempSK.D.Mod(tempSK.D, ecdsaK.k.PublicKey.Params().N)

			// Compute temporary public key
			tempX, tempY := ecdsaK.k.PublicKey.ScalarBaseMult(k.Bytes())
			tempSK.PublicKey.X, tempSK.PublicKey.Y =
				tempSK.PublicKey.Add(
					ecdsaK.k.PublicKey.X, ecdsaK.k.PublicKey.Y,
					tempX, tempY,
				)

			// Verify temporary public key is a valid point on the reference curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
			if !isOn {
				return nil, errors.New("Failed temporary public key IsOnCurve check. This is an foreign key.")
			}


			reRandomizedKey := &swECDSAPrivateKey{tempSK}

			// If the key is not Ephemeral, store it.
			if !opts.Ephemeral() {
				// Store the key
				err = csp.ks.storePrivateKey(hex.EncodeToString(reRandomizedKey.GetSKI()), tempSK)
				if err != nil {
					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
				}
			}

			return reRandomizedKey, nil

		default:
			return nil, errors.New("Opts not suppoted")

		}
	case *swAESPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		aesK := k.(*swAESPrivateKey)

		switch opts.(type) {
		case *HMACTruncated256AESDeriveKeyOpts:
			hmacOpts := opts.(*HMACTruncated256AESDeriveKeyOpts)

			hmacedKey := &swAESPrivateKey{primitives.HMACAESTruncated(aesK.k, hmacOpts.Argument()), false}

			// If the key is not Ephemeral, store it.
			if !opts.Ephemeral() {
				// Store the key
				err = csp.ks.storeKey(hex.EncodeToString(hmacedKey.GetSKI()), hmacedKey.k)
				if err != nil {
					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
				}
			}

			return hmacedKey, nil

		case *HMACDeriveKeyOpts:

			hmacOpts := opts.(*HMACDeriveKeyOpts)

			hmacedKey := &swAESPrivateKey{primitives.HMAC(aesK.k, hmacOpts.Argument()), true}

			// If the key is not Ephemeral, store it.
			if !opts.Ephemeral() {
				// Store the key
				err = csp.ks.storeKey(hex.EncodeToString(hmacedKey.GetSKI()), hmacedKey.k)
				if err != nil {
					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
				}
			}

			return hmacedKey, nil

		default:
			return nil, errors.New("Opts not suppoted")

		}

	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *P11BCCSP) KeyImport(raw []byte, opts KeyImportOpts) (k Key, err error) {
	// Validate arguments
	if len(raw) == 0 {
		return nil, errors.New("Invalid raw. Zero length.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. Nil.")
	}

	switch opts.(type) {
	case *AES256ImportKeyOpts:

		if len(raw) != 32 {
			return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(raw))
		}

		aesK := &swAESPrivateKey{utils.Clone(raw), false}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storeKey(hex.EncodeToString(aesK.GetSKI()), aesK.k)
			if err != nil {
				return nil, fmt.Errorf("Failed storing AES key [%s]", err)
			}
		}

		return aesK, nil
	case *HMACImportKeyOpts:

		aesK := &swAESPrivateKey{utils.Clone(raw), false}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storeKey(hex.EncodeToString(aesK.GetSKI()), aesK.k)
			if err != nil {
				return nil, fmt.Errorf("Failed storing AES key [%s]", err)
			}
		}

		return aesK, nil
	default:
		return nil, errors.New("Import Key Options not recognized")
	}
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *P11BCCSP) GetKey(ski []byte) (k Key, err error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("Invalid ski. Zero length.")
	}


	suffix := csp.ks.getSuffix(hex.EncodeToString(ski))

	switch suffix {
	case "key":
		// Load the key
		key, err := csp.ks.loadKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading key [%x] [%s]", ski, err)
		}

		return &swAESPrivateKey{key, false}, nil
	case "sk":
		// Load the private key
		key, err := csp.ks.loadPrivateKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *ecdsa.PrivateKey:
			return &swECDSAPrivateKey{key.(*ecdsa.PrivateKey)}, nil
		default:
			return nil, errors.New("Key type not recognized")
		}
	default:
		return nil, errors.New("Key not recognized")
	}
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *P11BCCSP) Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Zero length.")
	}

	// Check key type
	switch k.(type) {
	case *swECDSAPrivateKey:
		return k.(*swECDSAPrivateKey).k.Sign(rand.Reader, digest, nil)
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Verify verifies signature against key k and digest
func (csp *P11BCCSP) Verify(k Key, signature, digest []byte) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid key. Nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Zero length.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Zero length.")
	}

	// Check key type
	switch k.(type) {
	case *swECDSAPrivateKey:
		ecdsaSignature := new(primitives.ECDSASignature)
		_, err := asn1.Unmarshal(signature, ecdsaSignature)
		if err != nil {
			return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
		}

		return ecdsa.Verify(&(k.(*swECDSAPrivateKey).k.PublicKey), digest, ecdsaSignature.R, ecdsaSignature.S), nil
	default:
		return false, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *P11BCCSP) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Check key type
	switch k.(type) {
	case *swAESPrivateKey:
		// check for mode
		switch opts.(type) {
		case *AESCBCPKCS7ModeOpts, AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return primitives.CBCPKCS7Encrypt(k.(*swAESPrivateKey).k, plaintext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *P11BCCSP) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Check key type
	switch k.(type) {
	case *swAESPrivateKey:
		// check for mode
		switch opts.(type) {
		case *AESCBCPKCS7ModeOpts, AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return primitives.CBCPKCS7Decrypt(k.(*swAESPrivateKey).k, ciphertext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}
