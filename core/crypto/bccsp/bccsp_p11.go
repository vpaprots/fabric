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
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
	"github.com/miekg/pkcs11"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	p11BCCSPLog = logging.MustGetLogger("bccsp_p11")
	ctx         *pkcs11.Ctx
	sessions    = make(chan pkcs11.SessionHandle, 2000)
)

func initP11() {
	ctx = loadlib()
}

// P11BCCSP is the PKCS11-based implementation of the BCCSP.
// It is based on code used in the primitives package.
// It can be configured via vipe.
type P11BCCSP struct {
	// Still used to store Symmetric keys
	ks *swBCCSPKeyStore
}

type ecsigRS struct {
	R, S *big.Int
}

//-----  tvi's P11 stuff, redacted  ------------------------------------------
// how many Bytes of an SKI [hash(publickey)] to store as CKA_ID
const SKI_BYTES = 32

// SKI-to-pubkey and pubkey-to-SKI hashes both indexed by hex-string
// encodings of []byte [which is not allowed as key]
//
// hash[ SKI ] -> publickey
var ski2pubkey_h = make(map[string][]byte)

// hash[ publickey ] -> SKI
// could be computed (hash a portion); stored in CSP-persistent table instead
//
var pubkey2ski_h = make(map[string][]byte)

//--------------------------------------
// public key corresponding to previously seen SKI ['test and set']
// - sets pubkey if non-nil, and not yet in table
//
// ...add any SKI-specific lookup, session storage etc. here...
//
func ski2pubkey(ski []byte, pubkey []byte) []byte {
	skey := string(ski)

	pk, ok := ski2pubkey_h[skey]
	if !ok {
		if nil != pubkey {
			ski2pubkey_h[skey] = pubkey
			p11BCCSPLog.Debugf("ski2pubkey inserting pubkey\n%s\n", hex.Dump(pubkey))
		} else {
			p11BCCSPLog.Debugf("ski2pubkey could not find ski %s\n", hex.Dump(ski))
		}
		pk = nil
	}

	return pk
}

//--------------------------------------
// turn raw (R || S) into SEQUENCE { INT r, INT s }
//
func ecdsa_rs2asn(rs []byte) []byte {
	R := new(big.Int)
	S := new(big.Int)
	R.SetBytes(rs[0 : len(rs)/2])
	S.SetBytes(rs[len(rs)/2:])

	rs, err := asn1.Marshal(ecsigRS{R, S})
	if err != nil {
		p11BCCSPLog.Debugf("P11: RS -> ASN encoding failed [%s]", err)
		return nil
	}

	p11BCCSPLog.Debugf("RS[raw]\n%s\n", hex.Dump(rs))
	return rs
}

//--------------------------------------
// turn SEQUENCE { INT r, INT s } into []byte( R || S )
// nil if decoding failed
//
// R, S must be 00-padded to full length [that of curve coordinates]
//
func ecdsa_sig2rs(sig []byte) []byte {
	revsig := new(ecsigRS)
	_, err := asn1.Unmarshal(sig, revsig)

	if err != nil {
		p11BCCSPLog.Debugf("P11: R+S ASN encoding invalid [%s]", err)
		return nil
	}

	// XXX force to uniform size
	// rb = revsig.R.Bytes()
	// sb = revsig.S.Bytes()

	return append(revsig.R.Bytes(), revsig.S.Bytes()...)
}

//--------------------------------------
// reverse of ski2pubkey()
func pubkey2ski(pubkey []byte, ski []byte) []byte {
	pkey := string(pubkey)

	sk, ok := pubkey2ski_h[pkey]
	if !ok {
		if nil != ski {
			pubkey2ski_h[pkey] = ski
			p11BCCSPLog.Debugf("pubkey2ski inserting ski %s\n", hex.Dump(ski))
		} else {
			p11BCCSPLog.Debugf("pubkey2ski could not find pubkey\n%s\n", hex.Dump(pubkey))
		}
		sk = nil
	}

	return sk
}

//--------------------------------------
// caller must check for non-repeating ID, we just supply unique ctr here
// TODO: cross-image unicity [shall we pick this base/range from settings?]
var (
	BIGONE   = new(big.Int).SetInt64(1)
	id_ctr   = new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Lsh(BIGONE, 128))
	id_mutex sync.Mutex
)

func next_id_ctr() *big.Int {
	id_mutex.Lock()
	id_ctr = new(big.Int).Add(id_ctr, BIGONE)
	id_mutex.Unlock()
	p11BCCSPLog.Debugf("P11: id_ctr is now [%s]", id_ctr.Text(16))
	return id_ctr
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
	lib := viper.GetString("security.bccsp.pkcs11.library")
	if lib == "" {
		p11BCCSPLog.Fatalf("P11: no library default\n")
		return nil
	}

	pkcslib := pkcs11.New(lib)
	if pkcslib == nil {
		p11BCCSPLog.Fatalf("P11: instantiate failed [%s]\n", lib)
		return nil
	}

	pkcslib.Initialize()

	// insert first session so we can log in
	var slot uint = 4
	session, err := pkcslib.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: OpenSession [%s]\n", err)
	}

	pin := viper.GetString("security.bccsp.pkcs11.pin")
	if pin == "" {
		p11BCCSPLog.Fatal("P11: no PIN set\n")
	}
	err = pkcslib.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: login failed [%s]\n", err)
	}

	sessions <- session
	return pkcslib
}

func get_session() (session pkcs11.SessionHandle) {
	select {
	case session = <-sessions:
		// got one
	default:
		// create one
		var slot uint = 4
		s, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			p11BCCSPLog.Fatalf("P11: OpenSession [%s]\n", err)
		}
		session = s
	}
	return session
}

func return_session(session pkcs11.SessionHandle) {
	sessions <- session
}

//--------------------------------------
// does not manage sort-of-expected errors [not available etc.]
//
func list_attrs(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) error {
	var cktype, ckclass uint
	//	var cktoken, cksign, ckverify, ckpriv bool
	//	var ckecparam, ckecpoint, ckaid, cklabel []byte
	var ckecparam, ckaid, cklabel []byte

	if p11lib == nil {
		return nil
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckclass),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, cktype),

		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ckecparam),
		//		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ckecpoint),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaid),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cklabel),

		//		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, ckpriv),
		//		pkcs11.NewAttribute(pkcs11.CKA_SIGN, cksign),
		//		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, cktoken),
		//		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, ckverify),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, obj, template)
	if err != nil {
		p11BCCSPLog.Warningf("P11: get(attrlist) [%s]\n", err)
	}
	_ = attr

	for _, a := range attr {
		p11BCCSPLog.Debugf("P11: attr type %d/x%x, length %d b\n", a.Type, a.Type, len(a.Value))
		p11BCCSPLog.Debug(hex.Dump(a.Value))
	}

	return nil
}

//--------------------------------------
func ski2keyhandle(mod *pkcs11.Ctx, session pkcs11.SessionHandle, ski []byte, is_private bool) (pkcs11.ObjectHandle, error) {
	var noHandle pkcs11.ObjectHandle

	ktype := pkcs11.CKO_PUBLIC_KEY

	if is_private {
		ktype = pkcs11.CKO_PRIVATE_KEY
	}

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
		return noHandle, fmt.Errorf("P11: key not found")
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	}

	attr, err := mod.GetAttributeValue(session, objs[0], template)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: GAV [%s]\n", err)
	}

	// leave 'iterator' even if currently using only one entry
	for _, a := range attr {
		p11BCCSPLog.Debugf("attr type %d/x%x, length %d b, %d\n", a.Type, a.Type, len(a.Value), a.Value)
	}

	return objs[0], nil
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
		p11BCCSPLog.Fatalf("P11: get(EC point) [%s]\n", err)
	}
	_ = attr

	// leave 'iterator' even if currently using only one entry
	for _, a := range attr {
		if a.Type != pkcs11.CKA_EC_POINT {
			continue
		}
		p11BCCSPLog.Debugf("attr type %d/x%x, length %d b\n", a.Type, a.Type, len(a.Value))
		p11BCCSPLog.Debugf("EC point:\n")
		p11BCCSPLog.Debug(hex.Dump(a.Value))

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
		p11BCCSPLog.Debugf("EC-SPKI\n")
		p11BCCSPLog.Debug(hex.Dump(ski))
	}
	return ski
}

func generate_pkcs11(alg int, opts KeyGenOpts) (ski, ecpt []byte, err error) {
	_ = alg
	_ = opts

	p11lib := ctx

	session := get_session()
	defer return_session(session)

	id := next_id_ctr()
	ec_param_oid := algconst2oid(256)

	publabel := fmt.Sprintf("BCPUB%s", id.Text(16))
	prvlabel := fmt.Sprintf("BCPRV%s", id.Text(16))

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ec_param_oid),

		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),

		// WTLS attributes, not defined for other objects
		// setting these would allow storing the SKI
		// through sort-of-standard attributes
		//		pkcs11.NewAttribute(pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
		//                                    defaultSKI),
		//		pkcs11.NewAttribute(pkcs11.CKA_NAME_HASH_ALGORITHM,
		//		                    CKM_SHA256);
	}

	pub, prv, err := p11lib.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: keypair generate failed [%s]\n", err)
	}

	p11BCCSPLog.Debugf("P11 init/1")
	list_attrs(p11lib, session, prv)
	list_attrs(p11lib, session, pub)

	ecpt = ecpoint(p11lib, session, pub)
	ski = eckey2ski(p11lib, session, pub, ecpt)

	// save public-point <-> SKI mappings
	ski2pubkey(ski, ecpt)
	pubkey2ski(ecpt, ski)

	// set CKA_ID of the both keys to SKI(public key)
	//
	setski_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski[0:SKI_BYTES]),
	}

	p11BCCSPLog.Infof("Generated new P11 key, SKI %x\n", ski)
	//
	err = p11lib.SetAttributeValue(session, pub, setski_t)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
	}
	//
	err = p11lib.SetAttributeValue(session, prv, setski_t)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
	}

	p11BCCSPLog.Debugf("P11 init/2")
	list_attrs(p11lib, session, prv)
	list_attrs(p11lib, session, pub)

	return ski, ecpt, nil
}

//--------------------------------------
func sign_pkcs11(ski []byte, alg int, msg []byte) ([]byte, error) {
	p11lib := ctx
	session := get_session()
	defer return_session(session)

	p11BCCSPLog.Info("SKI(sign)\n")
	p11BCCSPLog.Debug(hex.Dump(ski))

	prvh, err := ski2keyhandle(p11lib, session, ski, true /*->private*/)
	if err != nil {
		p11BCCSPLog.Criticalf("P11: private key not found [%s]\n", err)
		return nil, err
	}

	err = p11lib.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		prvh)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: sign-initialize [%s]\n", err)
	}

	var sig []byte

	sig, err = p11lib.Sign(session, msg)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: sign failed [%s]\n", err)
	}

	return ecdsa_rs2asn(sig), nil
}

//--------------------------------------
// error is nil if verified
func verify_pkcs11(ski []byte, alg int, msg []byte, sig []byte) (valid bool, err error) {

	sig = ecdsa_sig2rs(sig)
	if sig == nil {
		return false, errors.New("P11: invalid signature encoding")
	}

	p11lib := ctx
	session := get_session()
	defer return_session(session)

	p11BCCSPLog.Debugf("SKI(verify)\n")
	p11BCCSPLog.Debug(hex.Dump(ski))

	pubh, err := ski2keyhandle(p11lib, session, ski, false /*->public*/)
	if err != nil {
		p11BCCSPLog.Criticalf("P11: public key not found [%s]\n", err)
		return false, err
	}

	err = p11lib.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		pubh)
	if err != nil {
		p11BCCSPLog.Criticalf("P11: verify-initialize [%s]\n", err)
		return false, err
	}
	err = p11lib.Verify(session, msg, sig)
	if err != nil {
		p11BCCSPLog.Warningf("P11: verify failed [%s]\n", err)
		return false, err
	}

	return true, nil
}

//-----  /tvi's P11 stuff  ---------------------------------------------------

var sha256abc = []byte("\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad")

func Eccycle() error {
	var ski, _, err = generate_pkcs11(0, nil)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: generate cycle failed [%s]", err)
	}

	sig, err := sign_pkcs11(ski, 0, sha256abc)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: sign cycle failed [%s]", err)
	}
	p11BCCSPLog.Debugf("signature('abc')\n")
	p11BCCSPLog.Debug(hex.Dump(sig))

	_, err = verify_pkcs11(ski, 0, sha256abc, sig)
	if err != nil {
		p11BCCSPLog.Fatalf("P11: verify[cycle] failed [%s]", err)
	}

	// cross-check: invalid signature MUST be rejected
	// P11 MAY return both 'signature invalid' or 'size of
	// signature invalid', which SHOULD be treated as the same
	//
	// TODO: we decided to return one error for these,
	// success, or any other error [unexpected, cause for concern]
	//
	sig = sig[0 : len(sig)-2]

	valid, err := verify_pkcs11(ski, 0, sha256abc, sig)
	if valid == true || err == nil {
		p11BCCSPLog.Fatalf("P11: invalid verify not rejected [%s]", err)
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
		// FIXME: what about opts.Ephemeral()
		ski, pub, err := generate_pkcs11(0, opts)
		if err != nil {
			return nil, fmt.Errorf("Failed ECDSA key.gen [%s]", err)
		}
		p11BCCSPLog.Infof("P11: generated SKI:\n")
		p11BCCSPLog.Debug(hex.Dump(ski))

		kpub := &p11ECDSAPublicKey{ski2spki(ski), "", ski}
		k = &p11ECDSAPrivateKey{kpub, "", ski}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = ioutil.WriteFile(csp.ks.conf.getPathForAlias(hex.EncodeToString((ski)), "sk"), pub, 0700)
			if err != nil {
				return nil, fmt.Errorf("Failed storing private key [%s]: [%s]", ski, err)
			}
		}

		//{ // DEBUG_CODE
		//if (false) {
		//	sig, err := sign_pkcs11(k.GetSKI(), 0, sha256abc)
		//	if err != nil {
		//		log.Fatalf("P11: sign cycle failed [%s]", err)
		//	}
		//	fmt.Printf("signature('abc')\n")
		//	fmt.Printf(hex.Dump(sig))
		//}
		//
		//	err = verify_pkcs11(k.GetSKI(), 0, sha256abc, sha256abc)
		//	if err != nil {
		//		fmt.Printf("P11: verify[1] failed [%s]", err)
		//	}
		//
		//	err = verify_pkcs11(k.GetSKI(), 0, sha256abc, append(sha256abc, sha256abc...))
		//	if err != nil {
		//		fmt.Printf("P11: verify[2] failed [%s]", err)
		//	}
		//}
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
	case *p11ECDSAPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid opts. Nil.")
		}

		//ecdsaK := k.(*swECDSAPrivateKey)

		switch opts.(type) {

		// Re-randomized an ECDSA private key
		case *ECDSAReRandKeyOpts:
			return nil, errors.New("HSM Derrivation not yet suppoted")
			//			reRandOpts := opts.(*ECDSAReRandKeyOpts)
			//			tempSK := &ecdsa.PrivateKey{
			//				PublicKey: ecdsa.PublicKey{
			//					Curve: ecdsaK.k.Curve,
			//					X:     new(big.Int),
			//					Y:     new(big.Int),
			//				},
			//				D: new(big.Int),
			//			}
			//
			//			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			//			var one = new(big.Int).SetInt64(1)
			//			n := new(big.Int).Sub(ecdsaK.k.Params().N, one)
			//			k.Mod(k, n)
			//			k.Add(k, one)
			//
			//			tempSK.D.Add(ecdsaK.k.D, k)
			//			tempSK.D.Mod(tempSK.D, ecdsaK.k.PublicKey.Params().N)
			//
			//			// Compute temporary public key
			//			tempX, tempY := ecdsaK.k.PublicKey.ScalarBaseMult(k.Bytes())
			//			tempSK.PublicKey.X, tempSK.PublicKey.Y =
			//				tempSK.PublicKey.Add(
			//					ecdsaK.k.PublicKey.X, ecdsaK.k.PublicKey.Y,
			//					tempX, tempY,
			//				)
			//
			//			// Verify temporary public key is a valid point on the reference curve
			//			isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
			//			if !isOn {
			//				return nil, errors.New("Failed temporary public key IsOnCurve check. This is an foreign key.")
			//			}
			//
			//			reRandomizedKey := &swECDSAPrivateKey{tempSK}
			//
			//			// If the key is not Ephemeral, store it.
			//			if !opts.Ephemeral() {
			//				// Store the key
			//				err = csp.ks.storePrivateKey(hex.EncodeToString(reRandomizedKey.GetSKI()), tempSK)
			//				if err != nil {
			//					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
			//				}
			//			}
			//
			//			return reRandomizedKey, nil

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
		p11BCCSPLog.Infof("Loading key [%x]\n", ski)

		path := csp.ks.conf.getPathForAlias(hex.EncodeToString((ski)), "sk")
		p11BCCSPLog.Debugf("Loading private key [%s] at [%s]...", ski, path)

		ecpt, err := ioutil.ReadFile(path)
		if err != nil {
			p11BCCSPLog.Errorf("Failed loading private key [%s]: [%s].", ski, err.Error())
			return nil, err
		}

		// save public-point <-> SKI mappings
		ski2pubkey(ski, ecpt)
		pubkey2ski(ecpt, ski)
		kpub := &p11ECDSAPublicKey{ski2spki(ski), "", ski}
		return &p11ECDSAPrivateKey{kpub, "", ski}, nil
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
		p11BCCSPLog.Info("P11 Sign\n")
		return sign_pkcs11(k.GetSKI(), 0, digest)
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
	case *p11ECDSAPrivateKey:
	case *p11ECDSAPublicKey:
		// <VP> Viper config for software signatures
		ecdsaSignature := new(primitives.ECDSASignature)
		_, err := asn1.Unmarshal(signature, ecdsaSignature)
		if err != nil {
			return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
		}

		p11BCCSPLog.Info("P11 Verify\n")
		//		if viper.GetBool("security.bccsp.pkcs11.swverify") == true {
		valid, err = verify_pkcs11(k.GetSKI(), 0, digest, signature)
		//            if err != nil {
		//				return false, err
		//			}
		//            // Delete from here to `return`
		//            raw, err := k.Bytes()
		//			if err != nil {
		//				return false, fmt.Errorf("Failed marshalling public key [%s]", err)
		//			}
		//
		//			pk, err := primitives.DERToPublicKey(raw)
		//			if err != nil {
		//				return false,fmt.Errorf("Failed marshalling public key [%s]", err)
		//			}
		//            valid2 := ecdsa.Verify(pk, digest, ecdsaSignature.R, ecdsaSignature.S)
		//
		//            if valid != valid2 {
		//            	p11BCCSPLog.Critical("Signature verification failed in HSM\n")
		//            }

		return valid, err
		//        } else {
		//            raw, err := k.Bytes()
		//			if err != nil {
		//				return false, fmt.Errorf("Failed marshalling public key [%s]", err)
		//			}
		//
		//			pk, err := primitives.DERToPublicKey(raw)
		//			if err != nil {
		//				return false, fmt.Errorf("Failed marshalling public key [%s]", err)
		//			}
		//            return ecdsa.Verify(pk, digest, ecdsaSignature.R, ecdsaSignature.S), nil
		//        }
	default:
		return false, fmt.Errorf("Key type not recognized [%s]", k)
	}
	return false, nil
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
