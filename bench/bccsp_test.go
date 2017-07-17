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
package main

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	_ "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw"

	"log"
	"net/http"
	_ "net/http/pprof"
)

var (
	msg1 = []byte("This is my very authentic message")
)

func TestMain(m *testing.M) {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	m.Run()
}

func BenchmarkCryptoECDSA(b *testing.B) {
	keystorePath := os.TempDir()
	lib, label, pin := pkcs11.FindPKCS11Lib()

	opts := &pkcs11.PKCS11Opts{
		HashFamily: "SHA2",
		SecLevel:   256,

		Library: lib,
		Label:   pin,
		Pin:     label,

		FileKeystore: &pkcs11.FileKeystoreOpts{
			KeyStorePath: keystorePath,
		},
	}

	keyStore, err := sw.NewFileBasedKeyStore(nil, keystorePath, false)
	if err != nil {
		b.Fatalf("Failed creating keystore [%s]", err)
	}

	csp, err := pkcs11.New(*opts, keyStore)
	if err != nil {
		b.Fatalf("Failed creating BCCSP [%s]", err)
	}

	key, err := csp.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
	if err != nil {
		b.Fatalf("Failed generating key for ECDSA [%s]", err)
	}

	hash, err := csp.Hash(msg1, &bccsp.SHA256Opts{})
	if err != nil {
		b.Fatalf("Failed generating hash for ECDSA [%s]", err)
	}

	signature, err := csp.Sign(key, hash, nil)
	if err != nil {
		b.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		b.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}

	b.SetParallelism(64)

	b.Run("HSMSignature", func(b *testing.B) { benchmarkSignature(b, csp, key) })
	b.Run("HSMVerify", func(b *testing.B) { benchmarkVerify(b, csp, key, signature) })

	b.Run("HSMParallelSignature", func(b *testing.B) { benchmarkParallelSignature(b, csp, key) })

	csp, err = sw.NewDefaultSecurityLevel(keystorePath)
	if err != nil {
		b.Fatalf("Failed creating BCCSP [%s]", err)
	}

	key, err = csp.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
	if err != nil {
		b.Fatalf("Failed generating key for ECDSA [%s]", err)
	}

	signature, err = csp.Sign(key, hash, nil)
	if err != nil {
		b.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		b.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}

	b.Run("SwSignature", func(b *testing.B) { benchmarkSignature(b, csp, key) })
	b.Run("SwVerify", func(b *testing.B) { benchmarkVerify(b, csp, key, signature) })

	b.Run("SwParallelSignature", func(b *testing.B) { benchmarkParallelSignature(b, csp, key) })
}

func benchmarkSignature(b *testing.B, csp bccsp.BCCSP, key bccsp.Key) {
	for i := 0; i < b.N; i++ {
		hash, err := csp.Hash(msg1, &bccsp.SHA256Opts{})
		if err != nil {
			b.Fatalf("Failed generating hash for ECDSA [%s]", err)
		}

		signature, err := csp.Sign(key, hash, nil)
		if err != nil {
			b.Fatalf("Failed generating ECDSA signature [%s]", err)
		}
		if len(signature) == 0 {
			b.Fatal("Failed generating ECDSA key. Signature must be different from nil")
		}
	}
}

func benchmarkVerify(b *testing.B, csp bccsp.BCCSP, key bccsp.Key, signature []byte) {
	for i := 0; i < b.N; i++ {
		hash, err := csp.Hash(msg1, &bccsp.SHA256Opts{})
		if err != nil {
			b.Fatalf("Failed generating hash for ECDSA [%s]", err)
		}

		valid, err := csp.Verify(key, signature, hash, nil)
		if err != nil {
			b.Fatalf("Failed verifying ECDSA signature [%s]", err)
		}
		if !valid {
			b.Fatal("Failed verifying ECDSA signature. Signature not valid.")
		}
	}
}

func benchmarkParallelSignature(b *testing.B, csp bccsp.BCCSP, key bccsp.Key) {
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			hash, _ := csp.Hash(msg1, &bccsp.SHA256Opts{})
			csp.Sign(key, hash, nil)
		}
	})
}
