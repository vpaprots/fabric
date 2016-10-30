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

package crypto

import (
	"math/big"

	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"

	"runtime/debug"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

func (node *nodeImpl) sign(signKey interface{}, msg []byte) ([]byte, error) {
	switch signKey.(type) {
	case bccsp.Key:
		csp, err := bccsp.GetDefault(int(node.GetType()))
		if err != nil {
			return nil, err
		}

		return csp.Sign(signKey.(bccsp.Key), primitives.Hash(msg), nil)
	default:
		log.Critical("node_sign sign got ecdsa.PrivateKey\n")
		debug.PrintStack()
		return primitives.ECDSASign(signKey, msg)
	}
}

func (node *nodeImpl) signWithEnrollmentKey(msg []byte) ([]byte, error) {
	csp, err := bccsp.GetDefault(int(node.GetType()))
	if err != nil {
		return nil, err
	}

	return csp.Sign(node.enrollPrivKey, primitives.Hash(msg), nil)
}

func (node *nodeImpl) ecdsaSignWithEnrollmentKey(msg []byte) (*big.Int, *big.Int, error) {
	csp, err := bccsp.GetDefault(int(node.GetType()))
	if err != nil {
		return nil, nil, err
	}

	signature, err := csp.Sign(node.enrollPrivKey, primitives.Hash(msg), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed generititc signature [%s]", err)
	}

	ecdsaSignature := new(primitives.ECDSASignature)
	_, err = asn1.Unmarshal(signature, ecdsaSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	return ecdsaSignature.R, ecdsaSignature.S, nil
}

func (node *nodeImpl) verify(verKey interface{}, msg, signature []byte) (bool, error) {
	return primitives.ECDSAVerify(verKey, msg, signature)
}

func (node *nodeImpl) verifyWithEnrollmentCert(msg, signature []byte) (bool, error) {
	return primitives.ECDSAVerify(node.enrollCert.PublicKey, msg, signature)
}

func (node *nodeImpl) verifySignCapability(tempSK interface{}, certPK interface{}) error {
	switch tempSK.(type) {
	case bccsp.Key:
		msg := []byte("This is a message to be signed and verified by ECDSA!")

		csp, err := bccsp.GetDefault(int(node.GetType()))
		if err != nil {
			return fmt.Errorf("Failed getting CSP [%s]", err)
		}

		sigma, err := csp.Sign(tempSK.(bccsp.Key), primitives.Hash(msg), nil)
		if err != nil {
			return fmt.Errorf("Failed generating signature [%s]", err)
		}

		ok, err := primitives.ECDSAVerify(certPK, msg, sigma)
		if err != nil {
			return fmt.Errorf("Failed verifycation [%s]", err)
		}

		if !ok {
			return errors.New("Keys incompatible.")
		}
	case *ecdsa.PrivateKey:
		log.Critical("verifySignCapability got ecdsa.PrivateKey\n")
		debug.PrintStack()

		msg := []byte("This is a message to be signed and verified by ECDSA!")

		sigma, err := primitives.ECDSASign(tempSK, msg)
		if err != nil {
			return fmt.Errorf("Failed generating signature [%s]", err)
		}

		ok, err := primitives.ECDSAVerify(certPK, msg, sigma)
		if err != nil {
			return fmt.Errorf("Failed verifycation [%s]", err)
		}

		if !ok {
			return errors.New("Keys incompatible.")
		}
	default:
		return errors.New("Key type not recognized.")
	}

	return nil
}
