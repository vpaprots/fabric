package bccsp

import (
	"errors"
	"fmt"
	"sync"
)

const (
	HSM_BASED_FACTORY_NAME = "H11"
)

type HSMBasedBCCSPFactory struct {
	defaultBCCSPInitOnce sync.Once
	defaultBCCSP         BCCSP
	defaultBCCSPError    error
}

func (f *HSMBasedBCCSPFactory) Name() string {
	return HSM_BASED_FACTORY_NAME
}

func (f *HSMBasedBCCSPFactory) Get(opts FactoryOpts) (BCCSP, error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. Nil.")
	}

	if opts.FactoryName() != f.Name() {
		return nil, fmt.Errorf("Invalid Provider Name [%s]. This is [%s]", opts.FactoryName(), f.Name())
	}

	if !opts.Ephemeral() {
		f.defaultBCCSPInitOnce.Do(func() {
			ks := &h11BCCSPKeyStore{}
			csp := &HSMBasedBCCSP{}
			if err := ks.init(csp, nil); err != nil {
				f.defaultBCCSPError = fmt.Errorf("Failed initializing key store [%s]", err)
				return
			}
			if err := csp.init(ks); err != nil {
				f.defaultBCCSPError = fmt.Errorf("Failed initializing HSMBasedBCCSP [%s]", err)
				return
			}
			f.defaultBCCSP = csp
			return
		})
		return f.defaultBCCSP, f.defaultBCCSPError
	}

	ks := &h11BCCSPKeyStore{}
	csp := &HSMBasedBCCSP{}
	if err := ks.init(csp, nil); err != nil {
		return nil, fmt.Errorf("Failed initializing key store [%s]", err)
	}
	
	if err := csp.init(ks); err != nil {
		return nil, fmt.Errorf("Failed initializing HSMBasedBCCSP [%s]", err)
	}
	return csp, nil

}
