/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package bench

import (
	"fmt"
	"os"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	_ "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw"
)

var (
	currentBCCSP      bccsp.BCCSP
	currentTestConfig testConfig
	msg1              = []byte("This is my very authentic message")
)

type NewCSP func(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error)

type testConfig struct {
	securityLevel int
	hashFamily    string
	key           *bccsp.Key
	hash          []byte
	signature     []byte
}

func TestMain(m *testing.M) {
	lib, pin, label := findPKCS11Lib()
	if enablePKCS11tests {
		err := pkcs11.InitPKCS11(lib, pin, label)
		if err != nil {
			fmt.Printf("Failed initializing PKCS11 library [%s]", err)
			os.Exit(-1)
		}
	} else {
		fmt.Printf("No PKCS11 library found!")
		os.Exit(-1)
	}

	tests := []testConfig{
		{securityLevel: 256, hashFamily: "SHA2"},
		{securityLevel: 256, hashFamily: "SHA3"},
		{securityLevel: 384, hashFamily: "SHA2"},
		{securityLevel: 384, hashFamily: "SHA3"},
	}

	for _, config := range tests {
		currentTestConfig = config

		fmt.Printf("Benchmarking PKCS11 at [%d, %s]\n", config.securityLevel, config.hashFamily)
		runOneBCCSP(m, pkcs11.New, config)

		fmt.Printf("Benchmarking GolangSW at [%d, %s]\n", config.securityLevel, config.hashFamily)
		runOneBCCSP(m, sw.New, config)
	}
	os.Exit(0)
}

func runOneBCCSP(m *testing.M, newCSP NewCSP, config testConfig) {
	var err error
	currentBCCSP, err = newCSP(config.securityLevel, config.hashFamily, &sw.DummyKeyStore{})
	if err != nil {
		fmt.Printf("Failed initiliazing BCCSP at [%d, %s]: [%s]", config.securityLevel, config.hashFamily, err)
		os.Exit(-1)
	}

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
	if err != nil {
		fmt.Printf("Failed generating ECDSA key [%s]", err)
		os.Exit(-1)
	}
	if k == nil {
		fmt.Printf("Failed generating ECDSA key. Key must be different from nil")
		os.Exit(-1)
	}
	currentTestConfig.key = &k

	currentTestConfig.hash, _ = currentBCCSP.Hash(msg1, &bccsp.SHAOpts{})
	signature, err := currentBCCSP.Sign(k, currentTestConfig.hash, nil)
	if err != nil {
		fmt.Printf("Failed generating ECDSA signature [%s]", err)
		os.Exit(-1)
	}
	if len(signature) == 0 {
		fmt.Printf("Failed generating ECDSA key. Signature must be different from nil")
		os.Exit(-1)
	}
	currentTestConfig.signature = signature

	ret := m.Run()
	if ret != 0 {
		fmt.Printf("Failed testing at [%d, %s]", config.securityLevel, config.hashFamily)
		os.Exit(-1)
	}
}

func BenchmarkKeyGenTemporary(b *testing.B) {
	for i := 0; i < b.N; i++ {
		k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
		if err != nil {
			b.Fatalf("Failed generating ECDSA key [%s]", err)
		}
		if k == nil {
			b.Fatal("Failed generating ECDSA key. Key must be different from nil")
		}
	}
}

func BenchmarkECSignature(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash, err := currentBCCSP.Hash(msg1, &bccsp.SHAOpts{})
		if err != nil {
			b.Fatalf("Failed generating hash for ECDSA [%s]", err)
		}

		if currentTestConfig.key == nil {
			b.Fatalf("KEY is nil.. INIT!")
		}
		signature, err := currentBCCSP.Sign(*currentTestConfig.key, hash, nil)
		if err != nil {
			b.Fatalf("Failed generating ECDSA signature [%s]", err)
		}
		if len(signature) == 0 {
			b.Fatal("Failed generating ECDSA key. Signature must be different from nil")
		}
	}
}

func BenchmarkECVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		valid, err := currentBCCSP.Verify(*currentTestConfig.key, currentTestConfig.signature, currentTestConfig.hash, nil)
		if err != nil {
			b.Fatalf("Failed verifying ECDSA signature [%s]", err)
		}
		if !valid {
			b.Fatal("Failed verifying ECDSA signature. Signature not valid.")
		}
	}
}

var enablePKCS11tests = false

func findPKCS11Lib() (lib, pin, label string) {
	//FIXME: Till we workout the configuration piece, look for the libraries in the familiar places
	lib = os.Getenv("PKCS11_LIB")
	if lib == "" {
		pin = "98765432"
		label = "ForFabric"
		possibilities := []string{
			"/usr/lib/softhsm/libsofthsm2.so",                            //Debian
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",           //Ubuntu
			"/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so",            //Ubuntu
			"/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so", //MacOS
		}
		for _, path := range possibilities {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				lib = path
				enablePKCS11tests = true
				break
			}
		}
		if lib == "" {
			enablePKCS11tests = false
		}
	} else {
		enablePKCS11tests = true
		pin = os.Getenv("PKCS11_PIN")
		label = os.Getenv("PKCS11_LABEL")
	}
	return lib, pin, label
}
