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
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v2"

	"gopkg.in/alecthomas/kingpin.v2"

	"bytes"
	"io/ioutil"

	"github.com/hyperledger/fabric/examples/e2e_cli/cryptogen/ca"
	"github.com/hyperledger/fabric/examples/e2e_cli/cryptogen/csp"
	"github.com/hyperledger/fabric/examples/e2e_cli/cryptogen/msp"
	"github.com/op/go-logging"
)

const (
	userBaseName            = "User"
	adminBaseName           = "Admin"
	defaultHostnameTemplate = "{{.Prefix}}{{.Index}}"
	defaultCNTemplate       = "{{.Hostname}}.{{.Domain}}"
)

type HostnameData struct {
	Prefix string
	Index  int
	Domain string
}

type CommonNameData struct {
	Hostname string
	Domain   string
}

type NodeTemplate struct {
	Count    int    `yaml:"Count"`
	Start    int    `yaml:"Start"`
	Hostname string `yaml:"Hostname"`
}

type NodeSpec struct {
	Hostname     string          `yaml:"Hostname"`
	AltHostnames []string        `yaml:"AltHostnames"`
	CommonName   string          `yaml:"CommonName"`
	PKCS11       *csp.PKCS11Opts `yaml:"PKCS11"`
}

type UsersSpec struct {
	Count int `yaml:"Count"`
}

type OrgSpec struct {
	Name          string          `yaml:"Name"`
	Domain        string          `yaml:"Domain"`
	Template      NodeTemplate    `yaml:"Template"`
	Specs         []NodeSpec      `yaml:"Specs"`
	Users         UsersSpec       `yaml:"Users"`
	DefaultPKCS11 *csp.PKCS11Opts `yaml:"PKCS11"`
}

type Config struct {
	OrdererOrgs []OrgSpec `yaml:"OrdererOrgs"`
	PeerOrgs    []OrgSpec `yaml:"PeerOrgs"`
}

var defaultConfig = `
# ---------------------------------------------------------------------------
# "OrdererOrgs" - Definition of organizations managing orderer nodes
# ---------------------------------------------------------------------------
OrdererOrgs:
  # ---------------------------------------------------------------------------
  # Orderer
  # ---------------------------------------------------------------------------
  - Name: Orderer
    Domain: example.com

    # ---------------------------------------------------------------------------
    # "Specs" - See PeerOrgs below for complete description
    # ---------------------------------------------------------------------------
    Specs:
      - Hostname: orderer

# ---------------------------------------------------------------------------
# "PeerOrgs" - Definition of organizations managing peer nodes
# ---------------------------------------------------------------------------
PeerOrgs:
  # ---------------------------------------------------------------------------
  # Org1
  # ---------------------------------------------------------------------------
  - Name: Org1
    Domain: org1.example.com

    # ---------------------------------------------------------------------------
    # "Specs"
    # ---------------------------------------------------------------------------
    # Uncomment this section to enable the explicit definition of hosts in your
    # configuration.  Most users will want to use Template, below
    #
    # Specs is an array of Spec entries.  Each Spec entry consists of three fields:
    #   - Hostname:   (Required) The desired hostname, sans the domain.
    #   - CommonName: (Optional) Specifies the template or explicit override for
    #                 the CN.  By default, this is the template:
    #
    #                              "{{.Hostname}}.{{.Domain}}"
    #
    #                 which obtains its values from the Spec.Hostname and
    #                 Org.Domain, respectively.
    #   - PKCS11: (Optional) If defined, this Spec will create private keys via a
    #             PKCS11 library. It must contain three fields:
    #             - Library: (Required) Path to pkcs11 shared library
    #             - Label: (Required) The label of the token to use
    #             - Pin: (Required) The pin for the above label
    # ---------------------------------------------------------------------------
    # Specs:
    #   - Hostname: foo # implicitly "foo.org1.example.com"
    #     CommonName: foo27.org5.example.com # overrides Hostname-based FQDN set above
    #   - Hostname: bar
    #   - Hostname: baz
    #     PKCS11:
    #       Library: /path/to/lib/softhsm/libsofthsm2.so
    #       Label: "ForFabricUser"
    #       Pin:   "1234"

    # ---------------------------------------------------------------------------
    # "Template"
    # ---------------------------------------------------------------------------
    # Allows for the definition of 1 or more hosts that are created sequentially
    # from a template. By default, this looks like "peer%d" from 0 to Count-1.
    # You may override the number of nodes (Count), the starting index (Start)
    # or the template used to construct the name (Hostname).
    #
    # Note: Template and Specs are not mutually exclusive.  You may define both
    # sections and the aggregate nodes will be created for you.  Take care with
    # name collisions
    # ---------------------------------------------------------------------------
    Template:
      Count: 1
      # Start: 5
      # Hostname: {{.Prefix}}{{.Index}} # default

    # ---------------------------------------------------------------------------
    # "Users"
    # ---------------------------------------------------------------------------
    # Count: The number of user accounts _in addition_ to Admin
    # ---------------------------------------------------------------------------
    Users:
      Count: 1
    
    # ---------------------------------------------------------------------------
    # "PKCS11"
    # ---------------------------------------------------------------------------
    # PKCS11: (Optional) If defined, this Spec will create private keys via a
    # PKCS11 library. It must contain three fields:
    #   - Library: (Required) Path to pkcs11 shared library
    #   - Label: (Required) The prefix of label of the token to use. The full label
    #            will be generated by {{.Label}}{{.Name}}. '@' symbols removed from
    #            the label
    #   - Pin: (Required) The pin for the above label
    #
    # PKCS11:
    #   Library: /path/to/lib/softhsm/libsofthsm2.so
    #   Label: "ForFabricUser"
    #   Pin:   "1234"
  # ---------------------------------------------------------------------------
  # Org2: See "Org1" for full specification
  # ---------------------------------------------------------------------------
  - Name: Org2
    Domain: org2.example.com
    Template:
      Count: 1
    Users:
      Count: 1
`

//command line flags
var (
	app = kingpin.New("cryptogen", "Utility for generating Hyperledger Fabric key material")

	gen        = app.Command("generate", "Generate key material")
	outputDir  = gen.Flag("output", "The output directory in which to place artifacts").Default("crypto-config").String()
	configFile = gen.Flag("config", "The configuration template to use").File()

	showtemplate = app.Command("showtemplate", "Show the default configuration template")
)

func main() {
	logging.SetLevel(logging.INFO, "bccsp")
	logging.SetLevel(logging.INFO, "bccsp_p11")
	logging.SetLevel(logging.INFO, "bccsp_sw")

	kingpin.Version("0.0.1")
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	// "generate" command
	case gen.FullCommand():
		generate()

	// "showtemplate" command
	case showtemplate.FullCommand():
		fmt.Print(defaultConfig)
		os.Exit(0)
	}
}

func getConfig() (*Config, error) {
	var configData string

	if *configFile != nil {
		data, err := ioutil.ReadAll(*configFile)
		if err != nil {
			return nil, fmt.Errorf("Error reading configuration: %s", err)
		}

		configData = string(data)
	} else {
		configData = defaultConfig
	}

	config := &Config{}
	err := yaml.Unmarshal([]byte(configData), &config)
	if err != nil {
		return nil, fmt.Errorf("Error Unmarshaling YAML: %s", err)
	}

	return config, nil
}

func generate() {

	config, err := getConfig()
	if err != nil {
		fmt.Printf("Error reading config: %s", err)
		os.Exit(-1)
	}

	for _, orgSpec := range config.PeerOrgs {
		err = generateNodeSpec(&orgSpec, "peer")
		if err != nil {
			fmt.Printf("Error processing peer configuration: %s", err)
			os.Exit(-1)
		}
		generatePeerOrg(*outputDir, orgSpec)
	}

	for _, orgSpec := range config.OrdererOrgs {
		generateNodeSpec(&orgSpec, "orderer")
		if err != nil {
			fmt.Printf("Error processing orderer configuration: %s", err)
			os.Exit(-1)
		}
		generateOrdererOrg(*outputDir, orgSpec)
	}
}

func parseTemplate(input, defaultInput string, data interface{}) (string, error) {

	// Use the default if the input is an empty string
	if len(input) == 0 {
		input = defaultInput
	}

	t, err := template.New("parse").Parse(input)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %s", err)
	}

	output := new(bytes.Buffer)
	err = t.Execute(output, data)
	if err != nil {
		return "", fmt.Errorf("Error executing template: %s", err)
	}

	return output.String(), nil
}

func generateNodeSpec(orgSpec *OrgSpec, prefix string) error {
	// First process all of our templated nodes
	for i := 0; i < orgSpec.Template.Count; i++ {
		data := HostnameData{
			Prefix: prefix,
			Index:  i + orgSpec.Template.Start,
			Domain: orgSpec.Domain,
		}

		hostname, err := parseTemplate(orgSpec.Template.Hostname, defaultHostnameTemplate, data)
		if err != nil {
			return err
		}

		spec := NodeSpec{Hostname: hostname}
		orgSpec.Specs = append(orgSpec.Specs, spec)
	}

	// And finally touch up all specs to add the domain
	for idx, spec := range orgSpec.Specs {
		data := CommonNameData{
			Hostname: spec.Hostname,
			Domain:   orgSpec.Domain,
		}

		finalCN, err := parseTemplate(spec.CommonName, defaultCNTemplate, data)
		if err != nil {
			return err
		}

		orgSpec.Specs[idx].CommonName = finalCN
	}

	return nil
}

func generatePeerOrg(baseDir string, orgSpec OrgSpec) {

	orgName := orgSpec.Domain

	fmt.Println(orgName)
	// generate CA
	orgDir := filepath.Join(baseDir, "peerOrganizations", orgName)
	caDir := filepath.Join(orgDir, "ca")
	mspDir := filepath.Join(orgDir, "msp")
	peersDir := filepath.Join(orgDir, "peers")
	usersDir := filepath.Join(orgDir, "users")
	adminCertsDir := filepath.Join(mspDir, "admincerts")
	rootCA, err := ca.NewCA(caDir, orgName, csp.FillOptsTemplate(orgSpec.DefaultPKCS11, orgName))
	if err != nil {
		fmt.Printf("Error generating CA for org %s:\n%v\n", orgName, err)
		os.Exit(1)
	}
	err = msp.GenerateVerifyingMSP(mspDir, rootCA)
	if err != nil {
		fmt.Printf("Error generating MSP for org %s:\n%v\n", orgName, err)
		os.Exit(1)
	}

	// add an admin user
	adminUserName := fmt.Sprintf("%s@%s", adminBaseName, orgName)
	generateNode(usersDir, adminUserName, rootCA, csp.FillOptsTemplate(orgSpec.DefaultPKCS11, adminUserName))

	// copy the admin cert to the org's MSP admincerts
	err = copyAdminCert(usersDir, adminCertsDir, adminUserName)
	if err != nil {
		fmt.Printf("Error copying admin cert for org %s:\n%v\n",
			orgName, err)
		os.Exit(1)
	}

	for _, spec := range orgSpec.Specs {
		peerName := spec.CommonName
		generateNode(peersDir, peerName, rootCA, spec.PKCS11)

		err = copyAdminCert(usersDir, filepath.Join(peersDir, peerName,
			"admincerts"), adminUserName)
		if err != nil {
			fmt.Printf("Error copying admin cert for org %s peer %s:\n%v\n",
				orgName, peerName, err)
			os.Exit(1)
		}
	}

	// TODO: add ability to specify usernames
	for j := 1; j <= orgSpec.Users.Count; j++ {
		userName := fmt.Sprintf("%s%d@%s", userBaseName, j, orgName)
		generateNode(usersDir, userName, rootCA, csp.FillOptsTemplate(orgSpec.DefaultPKCS11, userName))
	}
}

func copyAdminCert(usersDir, adminCertsDir, adminUserName string) error {
	// delete the contents of admincerts
	err := os.RemoveAll(adminCertsDir)
	if err != nil {
		return err
	}
	// recreate the admincerts directory
	err = os.MkdirAll(adminCertsDir, 0755)
	if err != nil {
		return err
	}
	err = copyFile(filepath.Join(usersDir, adminUserName, "signcerts",
		adminUserName+"-cert.pem"), filepath.Join(adminCertsDir,
		adminUserName+"-cert.pem"))
	if err != nil {
		return err
	}
	return nil

}

func generateNode(baseDir string, nodeName string, rootCA *ca.CA, hsmOpts *csp.PKCS11Opts) {
	nodeDir := filepath.Join(baseDir, nodeName)
	err := msp.GenerateLocalMSP(nodeDir, nodeName, rootCA, hsmOpts)
	if err != nil {
		fmt.Printf("Error generating local MSP for %s:\n%v\n", nodeName, err)
		os.Exit(1)
	}
}

func generateOrdererOrg(baseDir string, orgSpec OrgSpec) {

	orgName := orgSpec.Domain

	// generate CA
	orgDir := filepath.Join(baseDir, "ordererOrganizations", orgName)
	caDir := filepath.Join(orgDir, "ca")
	mspDir := filepath.Join(orgDir, "msp")
	orderersDir := filepath.Join(orgDir, "orderers")
	usersDir := filepath.Join(orgDir, "users")
	adminCertsDir := filepath.Join(mspDir, "admincerts")
	rootCA, err := ca.NewCA(caDir, orgName, csp.FillOptsTemplate(orgSpec.DefaultPKCS11, orgName))
	if err != nil {
		fmt.Printf("Error generating CA for org %s:\n%v\n", orgName, err)
		os.Exit(1)
	}
	err = msp.GenerateVerifyingMSP(mspDir, rootCA)
	if err != nil {
		fmt.Printf("Error generating MSP for org %s:\n%v\n", orgName, err)
		os.Exit(1)
	}

	adminUserName := fmt.Sprintf("%s@%s",
		adminBaseName, orgName)

	// generate an admin for the orderer org
	generateNode(usersDir, adminUserName, rootCA, csp.FillOptsTemplate(orgSpec.DefaultPKCS11, adminUserName))

	// copy the admin cert to the org's MSP admincerts
	err = copyAdminCert(usersDir, adminCertsDir, adminUserName)
	if err != nil {
		fmt.Printf("Error copying admin cert for org %s:\n%v\n",
			orgName, err)
		os.Exit(1)
	}

	for _, spec := range orgSpec.Specs {
		ordererName := spec.CommonName
		generateNode(orderersDir, ordererName, rootCA, spec.PKCS11)

		// copy the admin cert to each of the org's orderers's MSP admincerts
		err = copyAdminCert(usersDir, filepath.Join(orderersDir, ordererName,
			"admincerts"), adminUserName)
		if err != nil {
			fmt.Printf("Error copying admin cert for org %s orderer %s:\n%v\n",
				orgName, ordererName, err)
			os.Exit(1)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}
