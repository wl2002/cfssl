package transport

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// rotatingConfig is an auto-updating tls configuration.
type rotatingConfig struct {
	*tls.Config
	s   signer.Signer
	req *csr.CertificateRequest
}

// NewConfig creates a new auto-updating tls configuration.
func NewConfig(conf *tls.Config, s signer.Signer, req *csr.CertificateRequest) *tls.Config {
	c := &rotatingConfig{Config: conf, s: s, req: req}
	if c.Config == nil {
		c.Config = new(tls.Config)
	}
	c.addCert()
	go c.certCheckUp()
	return c.Config
}

func (c *rotatingConfig) certCheckUp() {
	interval := c.s.Policy().Default.Expiry / 2
	for now := range time.Tick(interval) {
		log.Infof("transport: checking %d cert chains at %v", len(c.Certificates), now)

		var haveGoodCert bool
		var expiryTime *time.Time

		for i, chain := range c.Certificates {
			var certs []*x509.Certificate
			for _, cert := range chain.Certificate {
				newcerts, err := x509.ParseCertificates(cert)
				if err != nil {
					log.Errorf("transport: couldn't parse certificate chain: %v", err)
					c.removeCert(i)
				}
				certs = append(certs, newcerts...)
			}

			expiryTime = helpers.ExpiryTime(certs)

			// Remove expired certificate chains
			if expiryTime == nil || expiryTime.Before(now) {
				log.Info("transport: cert has expired")
				c.removeCert(i)
			}

			// Mark that we have a cert that won't expire soon.
			if expiryTime.After(now.Add(2 * interval)) {
				haveGoodCert = true
			}
		}

		// Add a new cert if we don't have any long-lived ones.
		if !haveGoodCert {
			c.addCert()
		}
	}
}

func (c *rotatingConfig) removeCert(i int) {
	c.Certificates = append(c.Certificates[:i], c.Certificates[i+1:]...)
}

func (c *rotatingConfig) addCert() {
	csrPEM, keyPEM, err := csr.ParseRequest(c.req)
	if err != nil {
		log.Errorf("transport: couldn't parse certificate request: %v", err)
		return
	}

	certPEM, err := c.s.Sign(signer.SignRequest{Hosts: c.req.Hosts, Request: string(csrPEM)})
	if err != nil {
		log.Errorf("transport: couldn't sign certificate request: %v", err)
		return
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Errorf("transport: couldn't parse X.509 key pair: %v", err)
		return
	}
	c.Certificates = append([]tls.Certificate{cert}, c.Certificates...)
	log.Infof("There are now %d certificates.", len(c.Certificates))
	for _, cert := range c.Certificates {
		x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
		log.Infof("New cert good since %v ago", time.Now().Sub(x509Cert.NotBefore))
		log.Infof("New cert expires in %v", x509Cert.NotAfter.Sub(time.Now()))
	}
}
