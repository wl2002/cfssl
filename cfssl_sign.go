package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// Usage text of 'cfssl sign'
var signerUsageText = `cfssl sign -- signs a client cert with a host name by a given CA and CA key

Usage of sign:
        cfssl sign [-ca cert] [-ca-key key] [-config config] [-profile profile] [-remote host] [-label label] HOSTNAME CSR [SUBJECT]

Arguments:
        HOSTNAME:   Hostname for the cert
        CSR:        PEM file for certificate request, use '-' for reading PEM from stdin.

Note: HOSTNAME and CSR can also be supplied via flag values; flag values will take precedence over the argument.

SUBJECT is an optional file containing subject information to use for the certificate instead of the subject information in the CSR.

Flags:
`

// Flags of 'cfssl sign'
var signerFlags = []string{"hostname", "csr", "ca", "ca-key", "config", "profile", "label", "remote"}

// signerMain is the main CLI of signer functionality.
// [TODO: zi] Decide whether to drop the argument list and only use flags to specify all the inputs.
func signerMain(args []string) (err error) {
	// Grab values through args only if corresponding flags are absent
	if Config.hostname == "" {
		Config.hostname, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}
	if Config.certFile == "" {
		Config.certFile, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}

	var subjectData *signer.Subject
	if len(args) > 0 {
		var subjectFile string
		subjectFile, args, err = popFirstArgument(args)
		if err != nil {
			return
		}

		var subjectJSON []byte
		subjectJSON, err = ioutil.ReadFile(subjectFile)
		if err != nil {
			return
		}

		subjectData = new(signer.Subject)
		err = json.Unmarshal(subjectJSON, subjectData)
		if err != nil {
			return
		}
	}

	// Read the certificate and sign it with CA files
	log.Debug("Loading Client certificate: ", Config.certFile)
	clientCSR, err := readStdin(Config.certFile)
	if err != nil {
		return
	}

	// If there is a config, use its signing policy. Otherwise create a default policy
	var policy *config.Signing
	if Config.cfg != nil {
		policy = Config.cfg.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	// Make sure the policy reflects the new remote
	if Config.remote != "" {
		err = policy.OverrideRemotes(Config.remote)
		if err != nil {
			log.Infof("Invalid remote %v, reverting to configuration default", Config.remote)
			return
		}
	}

	// Note: a nil policy can be sent in here and a default one will be created
	// but we don't do that because we need to create one to hold the remote address
	sign, err := signer.NewSigner(Config.caFile, Config.caKeyFile, policy)
	if err != nil {
		return
	}

	req := signer.SignRequest{Config.hostname, string(clientCSR), subjectData, Config.profile, Config.label}

	cert, err := sign.Sign(req)
	if err != nil {
		return
	}
	fmt.Printf("%s", cert)
	return
}

// CLISigner assembles the definition of Command 'sign'
var CLISigner = &Command{signerUsageText, signerFlags, signerMain}
