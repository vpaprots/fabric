package bccsp

import (
	"errors"
	"fmt"
	"sync"
)

const (
	P11_BASED_FACTORY_NAME = "P11"
)

type P11BCCSPFactory struct {
	defaultBCCSPInitOnce sync.Once
	defaultBCCSP         BCCSP
	defaultBCCSPError    error
}

func (f *P11BCCSPFactory) Name() string {
	return P11_BASED_FACTORY_NAME
}

func (f *P11BCCSPFactory) Get(opts FactoryOpts) (BCCSP, error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. Nil.")
	}

	if opts.FactoryName() != f.Name() {
		return nil, fmt.Errorf("Invalid Provider Name [%s]. This is [%s]", opts.FactoryName(), f.Name())
	}

	if !opts.Ephemeral() {
		f.defaultBCCSPInitOnce.Do(func() {
			ks := &swBCCSPKeyStore{}
			if err := ks.init(nil); err != nil {
				f.defaultBCCSPError = fmt.Errorf("Failed initializing key store [%s]", err)
				return
			}
			f.defaultBCCSP = &P11BCCSP{ks}
			return
		})
		return f.defaultBCCSP, f.defaultBCCSPError
	}

	ks := &swBCCSPKeyStore{}
	if err := ks.init(nil); err != nil {
		return nil, fmt.Errorf("Failed initializing key store [%s]", err)
	}
	return &P11BCCSP{ks}, nil

}
