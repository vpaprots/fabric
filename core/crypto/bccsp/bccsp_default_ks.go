package bccsp

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"sync"

	"github.com/hyperledger/fabric/core/crypto/utils"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"errors"
	"fmt"
)

type defaultBCCSPKeyStore struct {
	conf *defaultBCCSPConfiguration
	
	isOpen bool

	pwd []byte

	// Sync
	m sync.Mutex
}

func (ks *defaultBCCSPKeyStore) init(pwd []byte) error {
	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("Keystore already Initilized.")
	}

	ks.conf = &defaultBCCSPConfiguration{}
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

	return nil
}

func (ks *defaultBCCSPKeyStore) isAliasSet(alias string) bool {
	missing, _ := utils.FilePathMissing(ks.conf.getPathForAlias(alias))
	if missing {
		return false
	}

	return true
}

func (ks *defaultBCCSPKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	rawKey, err := primitives.PrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias), rawKey, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) storePrivateKeyInClear(alias string, privateKey interface{}) error {
	rawKey, err := primitives.PrivateKeyToPEM(privateKey, nil)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias), rawKey, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) deletePrivateKeyInClear(alias string) error {
	return os.Remove(ks.conf.getPathForAlias(alias))
}

func (ks *defaultBCCSPKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias)
	defaultBCCSPLog.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := primitives.PEMtoPrivateKey(raw, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *defaultBCCSPKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := primitives.PublicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias), rawKey, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias)
	defaultBCCSPLog.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := primitives.PEMtoPublicKey(raw, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *defaultBCCSPKeyStore) storeKey(alias string, key []byte) error {
	pem, err := primitives.AEStoEncryptedPEM(key, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias), pem, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.conf.getPathForAlias(alias)
	defaultBCCSPLog.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	key, err := primitives.PEMtoAES(pem, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed parsing key [%s]: [%s]", alias, err)

		return nil, err
	}

	return key, nil
}

func (ks *defaultBCCSPKeyStore) storeCert(alias string, der []byte) error {
	err := ioutil.WriteFile(ks.conf.getPathForAlias(alias), primitives.DERCertToPEM(der), 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing certificate [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) certMissing(alias string) bool {
	return !ks.isAliasSet(alias)
}

func (ks *defaultBCCSPKeyStore) deleteCert(alias string) error {
	return os.Remove(ks.conf.getPathForAlias(alias))
}

func (ks *defaultBCCSPKeyStore) loadCert(alias string) ([]byte, error) {
	path := ks.conf.getPathForAlias(alias)
	defaultBCCSPLog.Debugf("Loading certificate [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading certificate [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return pem, nil
}

func (ks *defaultBCCSPKeyStore) loadExternalCert(path string) ([]byte, error) {
	defaultBCCSPLog.Debugf("Loading external certificate at [%s]...", path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading external certificate: [%s].", err.Error())

		return nil, err
	}

	return pem, nil
}

func (ks *defaultBCCSPKeyStore) loadCertX509AndDer(alias string) (*x509.Certificate, []byte, error) {
	path := ks.conf.getPathForAlias(alias)
	defaultBCCSPLog.Debugf("Loading certificate [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed loading certificate [%s]: [%s].", alias, err.Error())

		return nil, nil, err
	}

	cert, der, err := primitives.PEMtoCertificateAndDER(pem)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed parsing certificate [%s]: [%s].", alias, err.Error())

		return nil, nil, err
	}

	return cert, der, nil
}

func (ks *defaultBCCSPKeyStore) close() error {
	defaultBCCSPLog.Debug("Closing keystore...")
	defaultBCCSPLog.Debug("Closing keystore...done!")

	ks.isOpen = false
	return nil
}

func (ks *defaultBCCSPKeyStore) createKeyStoreIfNotExists() error {
	// Check keystore directory
	ksPath := ks.conf.getKeyStorePath()
	missing, err := utils.DirMissingOrEmpty(ksPath)
	defaultBCCSPLog.Debugf("Keystore path [%s] missing [%t]: [%s]", ksPath, missing, utils.ErrToString(err))

	if !missing {
		// Check keystore file
		missing, err = utils.FileMissing(ks.conf.getKeyStorePath(), ks.conf.getKeyStoreFilename())
		defaultBCCSPLog.Debugf("Keystore [%s] missing [%t]:[%s]", ks.conf.getKeyStoreFilePath(), missing, utils.ErrToString(err))
	}

	if missing {
		err := ks.createKeyStore()
		if err != nil {
			defaultBCCSPLog.Errorf("Failed creating db At [%s]: [%s]", ks.conf.getKeyStoreFilePath(), err.Error())
			return nil
		}
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.conf.getKeyStorePath()
	defaultBCCSPLog.Debugf("Creating Keystore at [%s]...", ksPath)

	missing, _ := utils.FileMissing(ksPath, ks.conf.getKeyStoreFilename())
	if !missing {
		defaultBCCSPLog.Debugf("Creating Keystore at [%s]. Keystore already there", ksPath)
		return nil
	}

	os.MkdirAll(ksPath, 0755)

	// Create Raw material folder
	os.MkdirAll(ks.conf.getRawsPath(), 0755)

	defaultBCCSPLog.Debugf("Keystore created at [%s].", ksPath)
	return nil
}

func (ks *defaultBCCSPKeyStore) deleteKeyStore() error {
	defaultBCCSPLog.Debugf("Removing KeyStore at [%s].", ks.conf.getKeyStorePath())

	return os.RemoveAll(ks.conf.getKeyStorePath())
}

func (ks *defaultBCCSPKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}

	// Open DB
	ksPath := ks.conf.getKeyStorePath()

	ks.isOpen = true

	defaultBCCSPLog.Debugf("Keystore opened at [%s]...done", ksPath)

	return nil
}
