package bccsp

import (
	"sync"
)

var (
	// Default BCCSP
	defaultBCCSP BCCSP

	// Sync on default bccsp creation
	m sync.Mutex
)

func GetDefault() (BCCSP, error) {
	if defaultBCCSP == nil {
		m.Lock()
		defer m.Unlock()
		if defaultBCCSP == nil {
			defaultBCCSP = &DefaultBCCSP{}
		}
	}

	return defaultBCCSP, nil
}
