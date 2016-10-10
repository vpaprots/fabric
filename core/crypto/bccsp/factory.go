package bccsp

import (
	"sync"
	"fmt"
)

var (
	// Default BCCSP
	defaultBCCSP *DefaultBCCSP

	// Sync on default bccsp creation
	m sync.Mutex
)

func GetDefault() (BCCSP, error) {
	if defaultBCCSP == nil {
		m.Lock()
		defer m.Unlock()
		if defaultBCCSP == nil {
			ks := &defaultBCCSPKeyStore{}
			if err := ks.init(nil); err != nil {
				return nil, fmt.Errorf("Failed initializing key store [%s]", err)
			}
			defaultBCCSP = &DefaultBCCSP{ks}
		}
	}

	return defaultBCCSP, nil
}
