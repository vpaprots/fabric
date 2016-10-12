package bccsp

import (
	"io/ioutil"
	"os"
	"sync"

	"github.com/hyperledger/fabric/core/crypto/utils"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"errors"
	"fmt"
	"strings"
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

func (ks *defaultBCCSPKeyStore) getSuffix(alias string) string {
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

func (ks *defaultBCCSPKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	rawKey, err := primitives.PrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "sk"), rawKey, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias, "sk")
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

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "pk"), rawKey, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.conf.getPathForAlias(alias, "pk")
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

	err = ioutil.WriteFile(ks.conf.getPathForAlias(alias, "key"), pem, 0700)
	if err != nil {
		defaultBCCSPLog.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.conf.getPathForAlias(alias, "key")
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
	defaultBCCSPLog.Infof("Keystore path [%s] missing [%t]: [%s]", ksPath, missing, utils.ErrToString(err))

	if missing {
		err := ks.createKeyStore()
		if err != nil {
			defaultBCCSPLog.Errorf("Failed creating ks At [%s]: [%s]", ksPath, err.Error())
			return nil
		}
	}

	return nil
}

func (ks *defaultBCCSPKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.conf.getKeyStorePath()
	defaultBCCSPLog.Debugf("Creating Keystore at [%s]...", ksPath)

	os.MkdirAll(ksPath, 0755)

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
