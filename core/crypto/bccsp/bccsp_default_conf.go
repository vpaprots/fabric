package bccsp

import (
	"errors"
	"path/filepath"

	"github.com/spf13/viper"
	"os"
)

type defaultBCCSPConfiguration struct {
	keystorePath      string

	configurationPathProperty string
}

func (conf *defaultBCCSPConfiguration) init() error {
	conf.configurationPathProperty = "security.bccsp.default.keyStorePath"

	// Check mandatory fields
	var rootPath string
	if err := conf.checkProperty(conf.configurationPathProperty); err != nil {
		defaultBCCSPLog.Warning("'security.bccsp.default.keyStorePath' not set. Using temp folder.")
		rootPath = os.TempDir()
	} else {
		rootPath = viper.GetString(conf.configurationPathProperty)
	}
	defaultBCCSPLog.Infof("Root Path [%s]", rootPath)
	// Set configuration path
	rootPath = filepath.Join(rootPath, "crypto")

	// Set ks path
	conf.keystorePath = filepath.Join(rootPath, "ks")

	return nil
}

func (conf *defaultBCCSPConfiguration) checkProperty(property string) error {
	res := viper.GetString(property)
	if res == "" {
		return errors.New("Property not specified in configuration file. Please check that property is set: " + property)
	}
	return nil
}

func (conf *defaultBCCSPConfiguration) getKeyStorePath() string {
	return conf.keystorePath
}

func (conf *defaultBCCSPConfiguration) getPathForAlias(alias string) string {
	return filepath.Join(conf.getKeyStorePath(), alias)
}


