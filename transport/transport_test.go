package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

var (
	network = "tcp"
	expiry  = 20 * time.Second
)

func serverFunc(conn *tls.Conn) {
	defer conn.Close()
	logger := log.New(os.Stdout, "[Server] ", log.LstdFlags)

	conn.SetReadDeadline(time.Now().Add(time.Second))
	io.Copy(conn, conn)
	logger.Printf("Accepted connection %v<=%v with ciphersuite %#04x\n", conn.LocalAddr(), conn.RemoteAddr(), conn.ConnectionState().CipherSuite)

	if len(conn.ConnectionState().PeerCertificates) > 0 {
		logger.Printf("Got certificate for: %s\n", conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	}
}

func clientFunc(conn *tls.Conn) error {
	defer conn.Close()
	logger := log.New(os.Stdout, "[Client] ", log.LstdFlags)

	if !conn.ConnectionState().HandshakeComplete {
		return errors.New("handshake didn't complete")
	}
	logger.Printf("Initiated connection %v=>%v with ciphersuite %#04x\n", conn.LocalAddr(), conn.RemoteAddr(), conn.ConnectionState().CipherSuite)
	logger.Printf("Got certificate for: %s\n", conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	logger.Printf("Server cert expires in %v\n", conn.ConnectionState().PeerCertificates[0].NotAfter.Sub(time.Now()))

	input := []byte("Hello World!")
	if _, err := conn.Write(input); err != nil {
		return err
	}

	output, err := ioutil.ReadAll(conn)
	if err != nil {
		return err
	}
	if bytes.Compare(input, output) != 0 {
		return errors.New("input and output do not match")
	}
	return nil
}

func testConfig(serverConfig, clientConfig *tls.Config) error {
	l, err := tls.Listen(network, clientConfig.ServerName, serverConfig)
	if err != nil {
		return err
	}
	defer l.Close()

	log.Printf("Listening at %s\n", l.Addr())
	go func() {
		for c, err := l.Accept(); err == nil; c, err = l.Accept() {
			go serverFunc(c.(*tls.Conn))
		}
	}()

	for {
		var dialer net.Dialer
		if len(clientConfig.Certificates) > 0 {
			var err error
			dialer.LocalAddr, err = net.ResolveTCPAddr(network, clientConfig.Certificates[0].Leaf.Subject.CommonName)
			if err != nil {
				return err
			}
		}

		conn, err := tls.DialWithDialer(&dialer, network, clientConfig.ServerName, clientConfig)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := clientFunc(conn); err != nil {
			return err
		}
		time.Sleep(time.Second * 5)
	}
}

// Pick a random ephemeral port
func randomPort() string {
	rand.Seed(time.Now().UnixNano())
	return strconv.Itoa(49152 + rand.Intn(65535-49152))
}

func NewSigner(expiry time.Duration) (signer.Signer, error) {
	certPEM, _, keyPEM, err := initca.New(&csr.CertificateRequest{CN: "Testing CA"})
	if err != nil {
		return nil, err
	}

	key, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	return local.NewSigner(
		key,
		cert,
		cert.SignatureAlgorithm,
		&config.Signing{
			Default: &config.SigningProfile{
				Usage:    []string{"server auth", "client auth"},
				Expiry:   expiry,
				Backdate: 1,
				CA:       false,
			},
		})
}

func getSignerRoot(s signer.Signer) (roots *x509.CertPool) {
	roots = x509.NewCertPool()
	resp, _ := s.Info(info.Req{})
	roots.AppendCertsFromPEM([]byte(resp.Certificate))
	return
}

func TestConfigServer(t *testing.T) {
	log.Printf("Expiry: %v", expiry)
	signer, err := NewSigner(expiry)
	if err != nil {
		t.Error(err)
	}

	server := net.JoinHostPort("127.0.0.1", randomPort())

	serverConfig := NewConfig(nil, signer, &csr.CertificateRequest{CN: server})
	clientConfig := &tls.Config{ServerName: server, RootCAs: getSignerRoot(signer)}

	if err := testConfig(serverConfig, clientConfig); err != nil {
		t.Error(err)
	}
}
