package signer

import (
	"encoding/json"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/config"
)

// A RemoteSigner represents a CFSSL instance running as signing server.
// fulfills the Signer interface
type RemoteSigner struct {
	policy  *config.Signing
}

// NewRemoteSigner creates a new RemoteSigner directly from a
// signing policy.
func NewRemoteSigner(policy *config.Signing) *RemoteSigner {
	return &RemoteSigner{policy: policy}
}

// Sign sends a signature request to the remote CFSSL server,
// receiving a signed certificate or an error in response. The hostname,
// csr, and profileName are used as with a local signing operation, and
// the label is used to select a signing root in a multi-root CA.
func (s *RemoteSigner) Sign(req SignRequest) (cert []byte, err error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.JSONError, err)
	}

	var profile *config.SigningProfile = nil
	if s.policy != nil && s.policy.Profiles != nil && req.Profile != "" {
		profile = s.policy.Profiles[req.Profile]
	}

	if profile == nil && s.policy != nil {
		profile = s.policy.Default
	}

	if profile.Provider != nil {
		cert, err = profile.Remote.AuthSign(jsonData, nil, profile.Provider)
	} else {
		cert, err = profile.Remote.Sign(jsonData)
	}

	return []byte(cert), nil
}

