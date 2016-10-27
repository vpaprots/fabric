package bccsp

import (
	"errors"
	"fmt"
	"sync"

	"github.com/spf13/viper"
)

var (
	// Default BCCSP
	defaultBCCSP BCCSP

	// BCCSP Factories
	factories map[string]Factory

	// factories' Sync on Initialization
	factoriesInitOnce sync.Once

	// Factories' Initialization Error
	factoriesInitError error
)

// Factory is used to get instances of the BCCSP interface.
// A Factory has name used to address it.
type Factory interface {
	Name() string

	Get(opts FactoryOpts) (BCCSP, error)
}

// FactoryOpts contains options for instantiating BCCSPs.
type FactoryOpts interface {

	// FactoryName returns the name of the factory to be used
	FactoryName() string

	// Ephemeral returns true if the BCCSP has to be ephemeral, false otherwise
	Ephemeral() bool
}

// GetDefault returns a non-ephemeral (long-term) BCCSP
func GetDefault() (BCCSP, error) {
	if err := initFactories(); err != nil {
		return nil, err
	}

	return defaultBCCSP, nil
}

// GetBCCSP returns a BCCSP created according to the options passed in input.
func GetBCCSP(opts FactoryOpts) (BCCSP, error) {
	if err := initFactories(); err != nil {
		return nil, err
	}

	return getBCCSPInternal(opts)
}

func initFactories() error {
	factoriesInitOnce.Do(func() {
		// Initialize factories map
		if factoriesInitError = initFactoriesMap(); factoriesInitError != nil {
			return
		}

		// Create default non-ephemeral (long-term) BCCSP
		defaultBCCSP, factoriesInitError = createDefaultBCCSP()
		if factoriesInitError != nil {
			return
		}
	})
	return factoriesInitError
}

func initFactoriesMap() error {
	factories = make(map[string]Factory)

	// Software-Based BCCSP
	sw := &SoftwareBasedBCCSPFactory{}
	factories[sw.Name()] = sw

	// PKCS11-Based BCCSP
	p11 := &P11BCCSPFactory{}
	factories[p11.Name()] = p11

	return nil
}

func createDefaultBCCSP() (BCCSP, error) {
	defaultBCCSPFactoryName := viper.GetString("security.bccsp.default")
	if defaultBCCSPFactoryName == "" {
		defaultBCCSPFactoryName = SOFTWARE_BASED_FACTORY_NAME
	}

	return getBCCSPInternal(&GenericFactoryOpts{defaultBCCSPFactoryName, false})
}

func getBCCSPInternal(opts FactoryOpts) (BCCSP, error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid options. Nil.")
	}

	f, ok := factories[opts.FactoryName()]
	if ok {
		return f.Get(opts)
	}

	return nil, fmt.Errorf("Factory [%s] does not exist.", opts.FactoryName())
}
