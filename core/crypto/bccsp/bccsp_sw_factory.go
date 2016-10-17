package bccsp

import (
	"errors"
	"fmt"
	"sync"
)

const (
	SOFTWARE_BASED_FACTORY_NAME = "SW"
)

type SoftwareBasedBCCSPFactory struct {
	defaultBCCSPInitOnce sync.Once
	defaultBCCSP         BCCSP
	defaultBCCSPError error
}

func (f *SoftwareBasedBCCSPFactory) Name() string {
	return SOFTWARE_BASED_FACTORY_NAME
}

func (f *SoftwareBasedBCCSPFactory) Get(opts FactoryOpts) (BCCSP, error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. Nil.")
	}

	if opts.FactoryName() != f.Name() {
		return nil, fmt.Errorf("Invalid Provider Name [%s]. This is [%d]", opts.FactoryName(), f.Name())
	}

	if !opts.Ephemeral() {
		f.defaultBCCSPInitOnce.Do(func() {
			ks := &swBCCSPKeyStore{}
			if err := ks.init(nil); err != nil {
				f.defaultBCCSPError = fmt.Errorf("Failed initializing key store [%s]", err)
				return
			}
			f.defaultBCCSP = &SoftwareBasedBCCSP{ks}
			return
		})
		return f.defaultBCCSP, f.defaultBCCSPError
	}

	ks := &swBCCSPKeyStore{}
	if err := ks.init(nil); err != nil {
		return nil, fmt.Errorf("Failed initializing key store [%s]", err)
	}
	return &SoftwareBasedBCCSP{ks}, nil

}

