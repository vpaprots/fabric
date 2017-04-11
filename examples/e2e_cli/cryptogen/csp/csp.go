/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/hyperledger/fabric/bccsp/signer"
)

// PKCS11Opts allows to enable pkcs11 support and specify library options.
// PKCS11 Token with Label label and Pin pin is expected to exist before
// cryptogen is invoked
type PKCS11Opts struct {
	Lib   string `yaml:"Library"`
	Label string `yaml:"Label"`
	Pin   string `yaml:"Pin"`
}

// FillOptsTemplate is a fairly dumb filler, if template is non-nil,
// copies template and appends suffix to label
func FillOptsTemplate(template *PKCS11Opts, suffix string) *PKCS11Opts {
	if template == nil {
		return nil
	}

	result := &PKCS11Opts{
		Lib:   template.Lib,
		Label: strings.Replace(fmt.Sprintf("%s%s", template.Label, suffix), "@", "", 1),
		Pin:   template.Pin,
	}

	return result
}

func getBCCSPOpts(keystorePath string, hsmOpts PKCS11Opts) *factory.FactoryOpts {
	providerName := "SW"
	if hsmOpts.Lib != "" {
		providerName = "PKCS11"
	}

	optsTemplate := &factory.FactoryOpts{
		ProviderName: providerName,
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
		Pkcs11Opts: &pkcs11.PKCS11Opts{
			HashFamily: "SHA2",
			SecLevel:   256,

			Library: hsmOpts.Lib,
			Label:   hsmOpts.Label,
			Pin:     hsmOpts.Pin,

			FileKeystore: &pkcs11.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}

	return optsTemplate
}

// GeneratePrivateKey creates a private key and stores it in keystorePath
func GeneratePrivateKey(keystorePath string, opts *PKCS11Opts) (bccsp.Key, crypto.Signer, error) {
	var hsmOpts PKCS11Opts
	if opts == nil {
		hsmOpts = PKCS11Opts{}
	} else {
		hsmOpts = *opts
	}

	csp, err := factory.GetBCCSPFromOpts(getBCCSPOpts(keystorePath, hsmOpts))
	if err != nil {
		return nil, nil, fmt.Errorf("Could not get BCCSP [%s]", err)
	}

	// generate a key
	priv, err := csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate key [%s]", err)
	}

	// create a crypto.Signer
	signer, err := signer.New(csp, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not get BCCSP signer [%s]", err)
	}

	return priv, signer, nil
}

func GetECPublicKey(priv bccsp.Key) (*ecdsa.PublicKey, error) {

	// get the public key
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}
	// unmarshal using pkix
	ecPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return ecPubKey.(*ecdsa.PublicKey), nil
}
