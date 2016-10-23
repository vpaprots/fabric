package bccsp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
	"github.com/op/go-logging"

	"github.com/miekg/pkcs11"
	"github.com/spf13/viper"
)

var (
	h11BCCSPLog = logging.MustGetLogger("bccsp_h11")
	counterLock sync.Mutex
	counter, _  = new(big.Int).SetString("fffffffe00000003fffffffd0000000200000001fffffffe0000000300000000", 16) //minv(2^256,p256) just for fun
)

// HSMBasedBCCSP is the software-based implementation of the BCCSP.
// It is based on code used in the primitives package.
// It can be configured via vipe.
type HSMBasedBCCSP struct {
	ks      *h11BCCSPKeyStore
	session *pkcs11.SessionHandle
	ctx     *pkcs11.Ctx
}

func (csp *HSMBasedBCCSP) init() (err error) {
	csp.session = nil

	lib := viper.GetString("security.bccsp.pkcs11.library")
	if lib == "" {
		return fmt.Errorf("security.bccsp.pkcs11.library not set!\n")
	}

	pin := viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		return fmt.Errorf("PIN not set, set security.bccsp.pkcs11.pin\n")
	}

	h11BCCSPLog.Debugf("Loading %s\n", lib)
	p := pkcs11.New(lib)
	if p == nil {
		return fmt.Errorf("Failed to load lib [%s]\n", lib)
	}

	if err := p.Initialize(); err != nil {
		return fmt.Errorf("Failed to Initialize [%s]\n", err)
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("Failed to GetSlotList [%s]\n", err)
	}

	session, err := p.OpenSession(slots[2], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		csp.session = nil
		return fmt.Errorf("Failed to OpenSession [%s]\n", err)
	}

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("Failed to Login [%s]\n", err)
	}

	csp.session = &session
	csp.ctx = p
	return nil
}

// KeyGen generates a key using opts.
func (csp *HSMBasedBCCSP) KeyGen(opts KeyGenOpts) (k Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid argument. Nil.")
	}

	// Parse algorithm
	switch opts.Algorithm() {
	case "ECDSA":

		counterLock.Lock()
		counter = new(big.Int).Add(counter, counter)
		counterLock.Unlock()
		tokenLabel := fmt.Sprintf("KEY%s", counter.Text(16))
		tokenPersistent := false //!opts.Ephemeral()

		publicKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"),
		}
		privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		}

		h11BCCSPLog.Debugf("GenerateKeyPair %s\n", tokenLabel)
		//pbk
		_, pvk, err := csp.ctx.GenerateKeyPair(*csp.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			publicKeyTemplate, privateKeyTemplate)

		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA key [[%s]", err)
		}

		lowLevelKey, err := primitives.NewECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA key [%s]", err)
		}

		k = &h11ECDSAPrivateKey{lowLevelKey}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.storePrivateKey(hex.EncodeToString(k.GetSKI()), lowLevelKey)
			if err != nil {
				return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
			}

			err = csp.ks.storePrivateKey2(tokenLabel, pvk)
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

		k = &h11AESPrivateKey{lowLevelKey, false}

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
	// return     // unreachable with current keytypes [linter]
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *HSMBasedBCCSP) KeyDeriv(k Key, opts KeyDerivOpts) (dk Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Derive key
	switch k.(type) {
	case *h11ECDSAPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		ecdsaK := k.(*h11ECDSAPrivateKey)

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

			reRandomizedKey := &h11ECDSAPrivateKey{tempSK}

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
	case *h11AESPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		aesK := k.(*h11AESPrivateKey)

		switch opts.(type) {
		case *HMACTruncated256AESDeriveKeyOpts:
			hmacOpts := opts.(*HMACTruncated256AESDeriveKeyOpts)

			hmacedKey := &h11AESPrivateKey{primitives.HMACAESTruncated(aesK.k, hmacOpts.Argument()), false}

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

			hmacedKey := &h11AESPrivateKey{primitives.HMAC(aesK.k, hmacOpts.Argument()), true}

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
func (csp *HSMBasedBCCSP) KeyImport(raw []byte, opts KeyImportOpts) (k Key, err error) {
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

		aesK := &h11AESPrivateKey{utils.Clone(raw), false}

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

		aesK := &h11AESPrivateKey{utils.Clone(raw), false}

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
func (csp *HSMBasedBCCSP) GetKey(ski []byte) (k Key, err error) {
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

		return &h11AESPrivateKey{key, false}, nil
	case "sk":
		// Load the private key
		key, err := csp.ks.loadPrivateKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *ecdsa.PrivateKey:
			return &h11ECDSAPrivateKey{key.(*ecdsa.PrivateKey)}, nil
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
func (csp *HSMBasedBCCSP) Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Zero length.")
	}

	// Check key type
	switch k.(type) {
	case *h11ECDSAPrivateKey:
		return k.(*h11ECDSAPrivateKey).k.Sign(rand.Reader, digest, nil)
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Verify verifies signature against key k and digest
func (csp *HSMBasedBCCSP) Verify(k Key, signature, digest []byte) (valid bool, err error) {
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
	case *h11ECDSAPrivateKey:
		ecdsaSignature := new(primitives.ECDSASignature)
		_, err := asn1.Unmarshal(signature, ecdsaSignature)
		if err != nil {
			return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
		}

		return ecdsa.Verify(&(k.(*h11ECDSAPrivateKey).k.PublicKey), digest, ecdsaSignature.R, ecdsaSignature.S), nil
	default:
		return false, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HSMBasedBCCSP) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Check key type
	switch k.(type) {
	case *h11AESPrivateKey:
		// check for mode
		switch opts.(type) {
		case *AESCBCPKCS7ModeOpts, AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return primitives.CBCPKCS7Encrypt(k.(*h11AESPrivateKey).k, plaintext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HSMBasedBCCSP) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid key. Nil.")
	}

	// Check key type
	switch k.(type) {
	case *h11AESPrivateKey:
		// check for mode
		switch opts.(type) {
		case *AESCBCPKCS7ModeOpts, AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return primitives.CBCPKCS7Decrypt(k.(*h11AESPrivateKey).k, ciphertext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}
