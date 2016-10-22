package bccsp

import (
	"errors"
	"path/filepath"

	"os"

	"github.com/spf13/viper"
)

type h11BCCSPConfiguration struct {
	keystorePath string

	configurationPathProperty string
}

func (conf *h11BCCSPConfiguration) init() error {
	conf.configurationPathProperty = "security.bccsp.keyStorePath"

	// Check mandatory fields
	var rootPath string
	if err := conf.checkProperty(conf.configurationPathProperty); err != nil {
		h11BCCSPLog.Warning("'security.bccsp.keyStorePath' not set. Using temp folder.")
		rootPath = os.TempDir()
	} else {
		rootPath = viper.GetString(conf.configurationPathProperty)
	}
	h11BCCSPLog.Infof("Root Path [%s]", rootPath)
	// Set configuration path
	rootPath = filepath.Join(rootPath, "crypto")

	// Set ks path
	conf.keystorePath = filepath.Join(rootPath, "ks")

	return nil
}

func (conf *h11BCCSPConfiguration) checkProperty(property string) error {
	res := viper.GetString(property)
	if res == "" {
		return errors.New("Property not specified in configuration file. Please check that property is set: " + property)
	}
	return nil
}

func (conf *h11BCCSPConfiguration) getKeyStorePath() string {
	return conf.keystorePath
}

func (conf *h11BCCSPConfiguration) getPathForAlias(alias, suffix string) string {
	return filepath.Join(conf.getKeyStorePath(), alias+"_"+suffix)
}
