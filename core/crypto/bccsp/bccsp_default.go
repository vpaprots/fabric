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
)

var (
	defaultBCCSPLog = logging.MustGetLogger("bccsp_default")
)




type DefaultBCCSP struct {
	ks *defaultBCCSPKeyStore
}

// GenKey generates a key using opts.
func (csp *DefaultBCCSP) GenKey(opts GenKeyOpts) (k Key, err error) {
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

		k = &ecdsaPrivateKey{lowLevelKey}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storePrivateKey(hex.EncodeToString(k.GetSKI()), lowLevelKey)
			if err != nil {
				return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
			}
		}

		return k, nil
	default:
		return nil, fmt.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
	}
	return
}

// DeriveKey derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *DefaultBCCSP) DeriveKey(k Key, opts DeriveKeyOpts) (dk Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Derive key
	switch k.(type) {
	case *ecdsaPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		ecdsaK := k.(*ecdsaPrivateKey)

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


			reRandomizedKey := &ecdsaPrivateKey{tempSK}

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
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *DefaultBCCSP) GetKey(ski []byte) (k Key, err error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("Invalid ski. Zero length.")
	}

	// Load the key
	key, err := csp.ks.loadPrivateKey(hex.EncodeToString(ski))
	if err != nil {
		return nil, fmt.Errorf("Failed loading key [%x] [%s]", ski, err)
	}

	switch key.(type) {
	case *ecdsa.PrivateKey:
		return &ecdsaPrivateKey{key.(*ecdsa.PrivateKey)}, nil
	default:
		return nil, errors.New("Key type not recognized")
	}
}

// ImportKey imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *DefaultBCCSP) ImportKey(raw []byte, opts ImportKeyOpts) (k Key, err error) {
	return nil, errors.New("Not imeplemtend yet")
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *DefaultBCCSP) Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Zero length.")
	}

	// Check key type
	switch k.(type) {
	case *ecdsaPrivateKey:
		return k.(*ecdsaPrivateKey).k.Sign(rand.Reader, digest, nil)
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Verify verifies signature against key k and digest
func (csp *DefaultBCCSP) Verify(k Key, signature, digest []byte) (valid bool, err error) {
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
	case *ecdsaPrivateKey:
		ecdsaSignature := new(primitives.ECDSASignature)
		_, err := asn1.Unmarshal(signature, ecdsaSignature)
		if err != nil {
			return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
		}

		return ecdsa.Verify(&(k.(*ecdsaPrivateKey).k.PublicKey), digest, ecdsaSignature.R, ecdsaSignature.S), nil
	default:
		return false, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *DefaultBCCSP) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error) {
	return nil, errors.New("Not imeplemtend yet")
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *DefaultBCCSP) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error) {
	return nil, errors.New("Not imeplemtend yet")
}
