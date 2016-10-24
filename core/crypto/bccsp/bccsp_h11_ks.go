package bccsp

import (
	"io/ioutil"
	"os"
	"sync"

	"github.com/hyperledger/fabric/core/crypto/utils"

	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/crypto/primitives"
// VT	"github.com/miekg/pkcs11"
)

type h11BCCSPKeyStore struct {
	conf *h11BCCSPConfiguration
	csp  *HSMBasedBCCSP
	isOpen bool

	pwd []byte

	// Sync
	m sync.Mutex
}

func (ks *h11BCCSPKeyStore) init(csp *HSMBasedBCCSP, pwd []byte) error {
	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("Keystore already Initilized.")
	}

	ks.conf = &h11BCCSPConfiguration{}
	err := ks.conf.init()
	if err != nil {
		return fmt.Errorf("Failed initializing configuration [%s]", err)
	}

	ks.pwd = utils.Clone(pwd)

	err = ks.createKeyStoreIfNotExists()
	if err != nil {
		return err
	}

	err = ks.openKeyStore()
	if err != nil {
		return err
	}
	
	ks.csp = csp

	return nil
}

func (ks *h11BCCSPKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ks.conf.getKeyStorePath())
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ks *h11BCCSPKeyStore) storePrivateKey2(alias string, privateKey interface{}) error {
	
	// Key already stored in the Opencryptoki keystore under 'alias' token
	// This is a emptt file to track ski type and debug
	
	err := ioutil.WriteFile(ks.conf.getPathForAlias(alias, "sk"), nil, 0700)
	if err != nil {
		h11BCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *h11BCCSPKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	rawKey, err := primitives.PrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "sk"), rawKey, 0700)
	if err != nil {
		h11BCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *h11BCCSPKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias, "sk")
	h11BCCSPLog.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		h11BCCSPLog.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := primitives.PEMtoPrivateKey(raw, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *h11BCCSPKeyStore) loadPrivateKey2(alias string) (interface{}, error) {
	
	// VT template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, alias)}
// VT	if err := ks.csp.ctx.FindObjectsInit(ks.csp.session, template); err != nil {
//	if nil {
//		h11BCCSPLog.Errorf("Failed to FindObjectsInit: %s\n", err)
//		return nil, err
//	}
//	obj, b, err := ks.csp.ctx.FindObjects(ks.csp.session, 2)
//	err := 0
//	if err != nil {
//		h11BCCSPLog.Errorf("Failed to FindObjects: %s %v\n", err, b)
//		return nil, err
//	}
//	if err := ks.csp.ctx.FindObjectsFinal(ks.csp.session); err != nil {
//		h11BCCSPLog.Errorf("Failed to FindObjectsFinal: %s\n", err)
//		return nil, err
//	}
	
//	return &h11ECDSAPrivateKey{nil, obj[0]/*privateP11Key*/, obj[1] /*publicP11Key*/, alias}, nil
	return &h11ECDSAPrivateKey{nil, 0/*privateP11Key*/, 0/*publicP11Key*/, alias}, nil
// /VT
}

func (ks *h11BCCSPKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := primitives.PublicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "pk"), rawKey, 0700)
	if err != nil {
		h11BCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *h11BCCSPKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias, "pk")
	h11BCCSPLog.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		h11BCCSPLog.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := primitives.PEMtoPublicKey(raw, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *h11BCCSPKeyStore) storeKey(alias string, key []byte) error {
	pem, err := primitives.AEStoEncryptedPEM(key, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "key"), pem, 0700)
	if err != nil {
		h11BCCSPLog.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *h11BCCSPKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.conf.getPathForAlias(alias, "key")
	h11BCCSPLog.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		h11BCCSPLog.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	key, err := primitives.PEMtoAES(pem, ks.pwd)
	if err != nil {
		h11BCCSPLog.Errorf("Failed parsing key [%s]: [%s]", alias, err)

		return nil, err
	}

	return key, nil
}

func (ks *h11BCCSPKeyStore) close() error {
	h11BCCSPLog.Debug("Closing keystore...")
	h11BCCSPLog.Debug("Closing keystore...done!")

	ks.isOpen = false
	return nil
}

func (ks *h11BCCSPKeyStore) createKeyStoreIfNotExists() error {
	// Check keystore directory
	ksPath := ks.conf.getKeyStorePath()
	missing, err := utils.DirMissingOrEmpty(ksPath)
	h11BCCSPLog.Infof("Keystore path [%s] missing [%t]: [%s]", ksPath, missing, utils.ErrToString(err))

	if missing {
		err := ks.createKeyStore()
		if err != nil {
			h11BCCSPLog.Errorf("Failed creating ks At [%s]: [%s]", ksPath, err.Error())
			return nil
		}
	}

	return nil
}

func (ks *h11BCCSPKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.conf.getKeyStorePath()
	h11BCCSPLog.Debugf("Creating Keystore at [%s]...", ksPath)

	os.MkdirAll(ksPath, 0755)

	h11BCCSPLog.Debugf("Keystore created at [%s].", ksPath)
	return nil
}

func (ks *h11BCCSPKeyStore) deleteKeyStore() error {
	h11BCCSPLog.Debugf("Removing KeyStore at [%s].", ks.conf.getKeyStorePath())

	return os.RemoveAll(ks.conf.getKeyStorePath())
}

func (ks *h11BCCSPKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}

	// Open DB
	ksPath := ks.conf.getKeyStorePath()

	ks.isOpen = true

	h11BCCSPLog.Debugf("Keystore opened at [%s]...done", ksPath)

	return nil
}
