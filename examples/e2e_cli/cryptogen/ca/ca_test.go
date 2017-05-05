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
package ca_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/examples/e2e_cli/cryptogen/ca"
	"github.com/hyperledger/fabric/examples/e2e_cli/cryptogen/csp"
	"github.com/stretchr/testify/assert"
)

const (
	testCAName  = "root0"
	testCA2Name = "root1"
	testName    = "cert0"
)

var testDir = filepath.Join(os.TempDir(), "ca-test")

func TestNewCA(t *testing.T) {

	caDir := filepath.Join(testDir, "ca")
	rootCA, err := ca.NewCA(caDir, testCAName, nil)
	assert.NoError(t, err, "Error generating CA")
	assert.NotNil(t, rootCA, "Failed to return CA")
	assert.NotNil(t, rootCA.Signer,
		"rootCA.Signer should not be empty")
	assert.IsType(t, &x509.Certificate{}, rootCA.SignCert,
		"rootCA.SignCert should be type x509.Certificate")

	// check to make sure the root public key was stored
	pemFile := filepath.Join(caDir, testCAName+"-cert.pem")
	assert.Equal(t, true, checkForFile(pemFile),
		"Expected to find file "+pemFile)
	cleanup(testDir)

}

func TestGenerateSignCertificate(t *testing.T) {

	caDir := filepath.Join(testDir, "ca")
	certDir := filepath.Join(testDir, "certs")
	// generate private key
	priv, _, err := csp.GeneratePrivateKey(certDir, nil)
	assert.NoError(t, err, "Failed to generate signed certificate")

	// get EC public key
	ecPubKey, err := csp.GetECPublicKey(priv)
	assert.NoError(t, err, "Failed to generate signed certificate")
	assert.NotNil(t, ecPubKey, "Failed to generate signed certificate")

	// create our CA
	rootCA, err := ca.NewCA(caDir, testCA2Name, nil)
	assert.NoError(t, err, "Error generating CA")

	err = rootCA.SignCertificate(certDir, testName, ecPubKey)
	assert.NoError(t, err, "Failed to generate signed certificate")

	// check to make sure the signed public key was stored
	pemFile := filepath.Join(certDir, testName+"-cert.pem")
	assert.Equal(t, true, checkForFile(pemFile),
		"Expected to find file "+pemFile)

	err = rootCA.SignCertificate(certDir, "empty/CA", ecPubKey)
	assert.Error(t, err, "Bad name should fail")

	// use an empty CA to test error path
	badCA := &ca.CA{
		Name:     "badCA",
		SignCert: &x509.Certificate{},
	}
	err = badCA.SignCertificate(certDir, testName, &ecdsa.PublicKey{})
	assert.Error(t, err, "Empty CA should not be able to sign")
	cleanup(testDir)

}

func cleanup(dir string) {
	os.RemoveAll(dir)
}

func checkForFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
