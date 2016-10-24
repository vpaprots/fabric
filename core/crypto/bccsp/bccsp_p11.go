package bccsp

// PKCS11 assumptions, with some based on Opencryptoki[ocki]
//
// - store SKI into CKA_ID; value matches for public/private halves of keypair
//   - sign/verify is indexed through SKI -> CKA_ID, see ski2keyhandle()
//   - we do not validate or re-calculate CKA_IDs we find
//   - a corresponding counter is inserted as CKA_LABEL
// - key generate and sign/verify MAY be separated 
//   - this precludes use of session objects, if the session may be terminated
//     - token objects may proliferate, need garbage collection [as with ICSF]
//   - may be able to preempt [maintain persistent connection to ocki?]
//   - reasonable session caching could save intervening getsession calls
//     - ocki does support multi-sessions
// - we do not expect CKA_EC_POINT to be set for EC private keys
//   - this is discussed as potential extension, non-standard, see:
//     https://wiki.oasis-open.org/pkcs11/DocumentClarifications [2016-10-23]
//     - there are already PKCS11 providers supplying it
// - assume login is required, without checking; PIN retrieved from settings
//   - ocki creates EP11-backed slots this way
// - assume publickey-to-SKI and SKI-to-publickey hashtables may grow
//   - ...we do not attempt to control their size


import (
	"crypto/ecdsa"
//	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
	//	"os"
	"github.com/hyperledger/fabric/core/crypto/utils"
	"github.com/spf13/viper"

	"github.com/miekg/pkcs11"

	"log"
	"sync/atomic" // unique-ID assignment
)

var (
	p11BCCSPLog = logging.MustGetLogger("bccsp_p11")
)

// P11BCCSP is the PKCS11-based implementation of the BCCSP.
// It is based on code used in the primitives package.
// It can be configured via vipe.
type P11BCCSP struct {
	ks *swBCCSPKeyStore
}

//-----  tvi's P11 stuff, redacted  ------------------------------------------
// how many Bytes of an SKI [hash(publickey)] to store as CKA_ID
const SKI_BYTES = 32

// SKI-to-pubkey and pubkey-to-SKI hashes both indexed by hex-string
// encodings of []byte [which is not allowed as key]
//
// hash[ SKI ] -> publickey
var ski2pubkey_h = make(map[string] []byte)

// hash[ publickey ] -> SKI
// could be computed (hash a portion); stored in CSP-persistent table instead
//
var pubkey2ski_h = make(map[string] []byte)


//--------------------------------------
// public key corresponding to previously seen SKI ['test and set']
// - sets pubkey if non-nil, and not yet in table
//
// ...add any SKI-specific lookup, session storage etc. here...
//
func ski2pubkey (ski []byte, pubkey []byte) []byte {
	skey := string(ski)

	pk, ok := ski2pubkey_h[ skey ]
	if (!ok) {
		if (nil != pubkey) {
			ski2pubkey_h[ skey ] = pubkey
		}
		pk = nil
	} 

	return pk
}


//--------------------------------------
// reverse of ski2pubkey()
func pubkey2ski (pubkey []byte, ski []byte) []byte {
	pkey := string(pubkey)

	sk, ok := pubkey2ski_h[ pkey ]
	if (!ok) {
		if (nil != ski) {
			pubkey2ski_h[ pkey ] = ski
		}
		sk = nil
	} 

	return sk
}



// label mgmt
// do not worry about index wrapping
var id_ctr uint64

//--------------------------------------
// caller must check for non-repeating ID, we just supply unique ctr here
// TODO: cross-image unicity [shall we pick this base/range from settings?]
func next_id_ctr() uint64 {
	return atomic.AddUint64(&id_ctr, 1)
}

//--------------------------------------
func algconst2oid(alg int) (oid []byte) {
	switch alg {
	case 384:
		return []byte("\x06\x05\x2b\x81\x04\x00\x22")
			// NIST P-384

	default:
	case 0:
	case 256:
		return []byte("\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07")
			// NIST P-256
	}
	return []byte("never reached")
}

//--------------------------------------
func loadlib() *pkcs11.Ctx {
	var lib = viper.GetString("security.bccsp.pkcs11.library")
	if lib == "" {
		log.Fatal("P11: no library default\n")
	}

	ps := pkcs11.New(lib)
	if ps == nil {
		fmt.Printf("P11: instantiate failed [%s]\n", lib)
	}
	return ps
}


//--------------------------------------
func ski2keyhandle(mod *pkcs11.Ctx, session pkcs11.SessionHandle, ski []byte, is_private bool) (pkcs11.ObjectHandle, error) {
	var noHandle pkcs11.ObjectHandle

	var ktype = pkcs11.CKO_PUBLIC_KEY

	if (is_private) {
		ktype = pkcs11.CKO_PRIVATE_KEY
	}
fmt.Printf("SKI(find)\n")
fmt.Printf(hex.Dump(ski))

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ktype),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}
	if err := mod.FindObjectsInit(session, template); err != nil {
		return noHandle, err
	}

		// single session instance, assume one hit only
	objs, _, err := mod.FindObjects(session, 1)
	if err != nil {
		return noHandle, err
	}
	if err = mod.FindObjectsFinal(session); err != nil {
		return noHandle, err
	}

	if len(objs) == 0 {
		return noHandle, fmt.Errorf("P11: private key not found")
	}

	return objs[0], nil
}



func generate_pkcs11() (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	var slot uint = 4 // ocki default

	var p11lib = loadlib()

	p11lib.Initialize()
	defer p11lib.Destroy()
	defer p11lib.Finalize()

	session, _ := p11lib.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	var id uint64 = next_id_ctr()
	var ec_param_oid = algconst2oid(256)

	var publabel = fmt.Sprintf("BCPUB%010d", id)
	var prvlabel = fmt.Sprintf("BCPRV%010d", id)

	var pin = viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		log.Fatal("P11: no PIN set\n")
	}
	p11lib.Login(session, pkcs11.CKU_USER, pin)
	defer p11lib.Logout(session)

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ec_param_oid),

		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),
	}

	pub, priv, err := p11lib.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)

	if err != nil {
		log.Fatal(err)
	}

	return pub, priv, nil

}

//-----  tvi sign/verify additions  ------------------------------------------

// fairly straightforward EC-point query, other than opencryptoki
// mis-reporting length, including the 04 Tag of the field following
// the SPKI in EP11-returned MACed publickeys:
//
// attr type 385/x181, length 66 b  -- SHOULD be 1+64
// EC point:
// 00000000  04 ce 30 31 6d 5a fd d3  53 2d 54 9a 27 54 d8 7c
// 00000010  d9 80 35 91 09 2d 6f 06  5a 8e e3 cb c0 01 b7 c9
// 00000020  13 5d 70 d4 e5 62 f2 1b  10 93 f7 d5 77 41 ba 9d
// 00000030  93 3e 18 3e 00 c6 0a 0e  d2 36 cc 7f be 50 16 ef
// 00000040  06 04
//
// cf. correct field:
//   0  89: SEQUENCE {
//   2  19:   SEQUENCE {
//   4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
//  13   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
//        :     }
//  23  66:   BIT STRING
//        :     04 CE 30 31 6D 5A FD D3 53 2D 54 9A 27 54 D8 7C
//        :     D9 80 35 91 09 2D 6F 06 5A 8E E3 CB C0 01 B7 C9
//        :     13 5D 70 D4 E5 62 F2 1B 10 93 F7 D5 77 41 BA 9D
//        :     93 3E 18 3E 00 C6 0A 0E D2 36 CC 7F BE 50 16 EF
//        :     06
//        :   }
//
// as a short-term workaround, remove the trailing byte if:
//   - receiving an even number of bytes == 2*prime-coordinate +2 bytes
//   - starting byte is 04: uncompressed EC point
//   - trailing byte is 04: assume it belongs to the next OCTET STRING
//
// [mis-parsing encountered with v3.5.1, 2016-10-22]
//
func ecpoint(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) []byte {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attr, err := p11lib.GetAttributeValue(session, key, template)
	if err != nil {
		log.Fatalf("P11: get(EC point) [%s]\n", err)
	}
	_ = attr

	// leave 'iterator' even if currently using only one entry
	for _, a := range attr {
		if a.Type != pkcs11.CKA_EC_POINT {
			continue
		}
		fmt.Printf("attr type %d/x%x, length %d b\n", a.Type, a.Type, len(a.Value))
		fmt.Printf("EC point:\n")
		fmt.Printf(hex.Dump(a.Value))

		// workaround, see above
		if (0 == (len(a.Value) % 2)) && (byte(0x04) == a.Value[0]) && (byte(0x04) == a.Value[len(a.Value)-1]) {
			return a.Value[0 : len(a.Value)-1]
		}

		return a.Value
	}

	return nil
}

// non-nil ecpt supplies EC point; nil queries EC key object
// SKI [depending only on public key] is identical for matching keypair
//
// accepts 04 <X> <Y> form, or raw <X> <Y> with X,Y 00-padded to uniform size
//
// returns nil if format not recognized
//
func eckey2ski(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, ecpt []byte) []byte {
	if ecpt == nil {
		ecpt = ecpoint(p11lib, session, key)
	}

	if ecpt != nil {
		if 1 == len(ecpt)%2 { // strip 04 from "04 <X> <Y>"
			if byte(0x04) == ecpt[0] {
				ecpt = ecpt[1:]
			} else {
				return nil // <non-04> <X> <Y>
			}
		}

		// hashes are unaddressable
		// slice copy of result
		hash := sha256.Sum256(ecpt)
		ecpt = hash[:]
	}

	return ecpt
}

var ec_p256_spkibase = []byte("\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00")

// returns nil if SKI not yet known
// XXX restricted to EC/P256
func ski2spki(ski []byte) []byte {
	ski = ski2pubkey(ski, nil)
	if nil != ski {
			// SPKI base for EC-P256
		ski = append(ec_p256_spkibase, ski...)
		fmt.Printf("EC-SPKI\n")
		fmt.Printf(hex.Dump(ski))
	}
	return ski
}

func Generate_pkcs11(alg int) (ski []byte, err error) {
	var slot uint = 4 // ocki default

	_ = alg

	var p11lib = loadlib()

	p11lib.Initialize()
	defer p11lib.Destroy()
	defer p11lib.Finalize()

	session, _ := p11lib.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	var id uint64 = next_id_ctr()
	var ec_param_oid = algconst2oid(256)

	var publabel = fmt.Sprintf("BCPUB%010d", id)
	var prvlabel = fmt.Sprintf("BCPRV%010d", id)

	var pin = viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		log.Fatal("P11: no PIN set\n")
	}
	p11lib.Login(session, pkcs11.CKU_USER, pin)
	defer p11lib.Logout(session)

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ec_param_oid),

		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),

		// WTLS attributes, not defined for other objects
		// setting these would allow storing the SKI
		//		pkcs11.NewAttribute(pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
		//                                    defaultSKI),
		//		pkcs11.NewAttribute(pkcs11.CKA_NAME_HASH_ALGORITHM,
		//		                    CKM_SHA256);
	}

	pub, prv, err := p11lib.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)
	if err != nil {
		log.Fatalf("P11: keypair generate failed [%s]\n", err)
	}

	{
		ecpt := ecpoint(p11lib, session, pub)
		ski := eckey2ski(p11lib, session, pub, ecpt)

		// save public-point <-> SKI mappings
		ski2pubkey(ski, ecpt)
		pubkey2ski(ecpt, ski)
fmt.Printf("SKI(set)\n")
fmt.Printf(hex.Dump(ski))

		// set CKA_ID of the both keys to SKI(private key)
		//
		setski_t := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, ski[0:SKI_BYTES]),
		}
		//
		err = p11lib.SetAttributeValue(session, pub, setski_t)
		if err != nil {
			log.Fatalf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
		}
		//
		err = p11lib.SetAttributeValue(session, prv, setski_t)
		if err != nil {
			log.Fatalf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
		}

		return ski, nil
	}
}

//--------------------------------------
func Sign_pkcs11(ski []byte, alg int, msg []byte) ([]byte, error) {
	var slot uint = 4
	var p11lib = loadlib()

	p11lib.Initialize()
	defer p11lib.Destroy()
	defer p11lib.Finalize()

	var session, _ = p11lib.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	var pin = viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		log.Fatal("P11: no PIN set\n")
	}
	p11lib.Login(session, pkcs11.CKU_USER, pin)
	defer p11lib.Logout(session)

	fmt.Printf("SKI(sign)\n")
	fmt.Printf(hex.Dump(ski))

	var prvh, err = ski2keyhandle(p11lib, session, ski, true /*->private*/)
	if err != nil {
		log.Fatalf("P11: private key not found [%s]\n", err)
	}

	err = p11lib.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		prvh)
	if err != nil {
		log.Fatalf("P11: sign-initialize [%s]\n", err)
	}

	var sig []byte

	sig, err = p11lib.Sign(session, msg)
	if err != nil {
		log.Fatalf("P11: sign failed [%s]\n", err)
	}

	return sig, nil
}

//--------------------------------------
// error is nil if verified
func Verify_pkcs11(ski []byte, alg int, msg []byte, sig []byte) error {
	var slot uint = 4
	var p11lib = loadlib()

	var session, _ = p11lib.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	var pin = viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		log.Fatal("P11: no PIN set\n")
	}
	p11lib.Login(session, pkcs11.CKU_USER, pin)
	defer p11lib.Logout(session)

	var pubh, err = ski2keyhandle(p11lib, session, ski, false /*->public*/)
	if err != nil {
		log.Fatalf("P11: public key not found [%s]\n", err)
	}

	err = p11lib.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		pubh)
	if err != nil {
		log.Fatalf("P11: verify-initialize [%s]\n", err)
	}
	err = p11lib.Verify(session, msg, sig)
	if err != nil {
		log.Printf("P11: verify failed [%s]\n", err)
		return err
	}

	return nil
}

//-----  /tvi's P11 stuff  ---------------------------------------------------

var sha256abc = []byte("\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad")

func Eccycle() error {
	var ski, err = Generate_pkcs11(0)
	if err != nil {
		log.Fatalf("P11: generate cycle failed [%s]", err)
	}

	sig, err := Sign_pkcs11(ski, 0, sha256abc)
	if err != nil {
		log.Fatalf("P11: sign cycle failed [%s]", err)
	}
	fmt.Printf("signature('abc')\n")
	fmt.Printf(hex.Dump(sig))

	err = Verify_pkcs11(ski, 0, sha256abc, sig)
	if err != nil {
		log.Fatalf("P11: verify[cycle] failed [%s]", err)
	}

	// cross-check: invalid signature MUST be rejected
	// P11 MAY return both 'signature invalid' or 'size of
	// signature invalid', which SHOULD be treated as the same
	//
	// TODO: we decided to return one error for these,
	// success, or any other error [unexpected, cause for concern]
	//
	sig = sig[0 : len(sig)-2]

	err = Verify_pkcs11(ski, 0, sha256abc, sig)
	if err == nil {
		log.Fatalf("P11: invalid verify not rejected [%s]", err)
	}

	return nil
}

//-----  /tvi's P11 test stuff  ----------------------------------------------

// KeyGen generates a key using opts.
func (csp *P11BCCSP) KeyGen(opts KeyGenOpts) (k Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid argument. Nil.")
	}

	// Parse algorithm
	switch opts.Algorithm() {
	case "ECDSA":
		// generate an ECDSA key through P11
		// ...which will then be discarded...
		//
		ski, err := Generate_pkcs11(0)
		if err != nil {
			return nil, fmt.Errorf("Failed ECDSA key.gen [%s]", err)
		}
		fmt.Printf("P11: generated SKI:\n")
		fmt.Printf(hex.Dump(ski))

		kpub := &p11ECDSAPublicKey{ski2spki(ski), "", ski}
		k = &p11ECDSAPrivateKey{kpub, "", ski}

{
	sig, err := Sign_pkcs11(k.GetSKI(), 0, sha256abc)
	if err != nil {
		log.Fatalf("P11: sign cycle failed [%s]", err)
	}
	fmt.Printf("signature('abc')\n")
	fmt.Printf(hex.Dump(sig))

	err = Verify_pkcs11(ski, 0, sha256abc, sig)
	if err != nil {
		log.Fatalf("P11: verify[cycle] failed [%s]", err)
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
	case *p11ECDSAPrivateKey:
		return Sign_pkcs11(k.GetSKI(), 0, digest)
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

		err = Verify_pkcs11(k.GetSKI(), 0, digest, signature)
		if err == nil {
		}
		return true, nil
//		return ecdsa.Verify(&(k.(*swECDSAPrivateKey).k.PublicKey), digest, ecdsaSignature.R, ecdsaSignature.S), nil
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
