package bccsp

import (
	"errors"
	"path/filepath"

	"github.com/spf13/viper"
)

type defaultBCCSPConfiguration struct {
	prefix string
	name   string

	logPrefix string

	rootDataPath      string
	configurationPath string
	keystorePath      string
	rawsPath          string
	tCertsPath        string

	configurationPathProperty string

}

func (conf *defaultBCCSPConfiguration) init() error {
	conf.configurationPathProperty = "peer.fileSystemPath"

	// Check mandatory fields
	if err := conf.checkProperty(conf.configurationPathProperty); err != nil {
		return err
	}

	conf.configurationPath = viper.GetString(conf.configurationPathProperty)
	conf.rootDataPath = conf.configurationPath

	// Set configuration path
	conf.configurationPath = filepath.Join(
		conf.configurationPath,
		"crypto", conf.prefix, conf.name,
	)

	// Set ks path
	conf.keystorePath = filepath.Join(conf.configurationPath, "ks")

	// Set raws path
	conf.rawsPath = filepath.Join(conf.keystorePath, "raw")

	// Set tCerts path
	conf.tCertsPath = filepath.Join(conf.keystorePath, "tcerts")

	return nil
}

func (conf *defaultBCCSPConfiguration) checkProperty(property string) error {
	res := viper.GetString(property)
	if res == "" {
		return errors.New("Property not specified in configuration file. Please check that property is set: " + property)
	}
	return nil
}

func (conf *defaultBCCSPConfiguration) getConfPath() string {
	return conf.configurationPath
}

func (conf *defaultBCCSPConfiguration) getKeyStorePath() string {
	return conf.keystorePath
}

func (conf *defaultBCCSPConfiguration) getRootDatastorePath() string {
	return conf.rootDataPath
}

func (conf *defaultBCCSPConfiguration) getRawsPath() string {
	return conf.rawsPath
}

func (conf *defaultBCCSPConfiguration) getKeyStoreFilename() string {
	return "db"
}

func (conf *defaultBCCSPConfiguration) getKeyStoreFilePath() string {
	return filepath.Join(conf.getKeyStorePath(), conf.getKeyStoreFilename())
}


func (conf *defaultBCCSPConfiguration) getPathForAlias(alias string) string {
	return filepath.Join(conf.getRawsPath(), alias)
}


