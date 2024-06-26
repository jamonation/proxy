package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	mathrand "math/rand"
	"os"
	"time"
)

var (
	caKey  string
	caCert string
	caPair tls.Certificate
)

func init() {
	var ok bool
	var err error

	if caCert, ok = os.LookupEnv("CA_CERT"); !ok {
		log.Fatal("missing CA_CERT environment variable")
	}
	if caKey, ok = os.LookupEnv("CA_KEY"); !ok {
		log.Fatal("missing CA_KEY environment variable")
	}

	caPair, err = tls.X509KeyPair([]byte(caCert), []byte(caKey))
	if err != nil {
		log.Fatalf("error loading CA key pair: %v", err)
	}
}

// makeCert creates a new TLS certificate, and signs it
func makeCert(hostname string) (*bytes.Buffer, *bytes.Buffer) {
	caCert, _ := x509.ParseCertificate(caPair.Certificate[0])

	certPkix := pkix.Name{
		CommonName:         hostname,
		Country:            []string{"US"},
		Province:           []string{"WA"},
		Locality:           []string{"Kirkland"},
		Organization:       []string{"Chainguard"},
		OrganizationalUnit: []string{"Academy"},
	}

	certSerial := &big.Int{}
	randSeed := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	// populate cert template
	template := x509.Certificate{
		DNSNames:           []string{hostname},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(1 * time.Hour),
		Subject:            certPkix,
		SignatureAlgorithm: x509.PureEd25519, // the CA keypair must use ed25519 private key for this to work
		SerialNumber:       certSerial.SetInt64(randSeed.Int63()),
	}

	// create ed25519 key pair
	certPubKey, certPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// encode the private key
	certPrivKeyBuf := new(bytes.Buffer)
	certPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	err = pem.Encode(certPrivKeyBuf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: certPrivKeyBytes,
	})
	if err != nil {
		panic(err)
	}

	// create the TLS certificate and sign using the CA cert
	certBytes, err := x509.CreateCertificate(
		rand.Reader,       // crypto rand.reader
		&template,         // populated certificate fields
		caCert,            // the ca public certificate
		certPubKey,        // sign the public key with the ca private key
		caPair.PrivateKey, // the ca private key
	)
	if err != nil {
		panic(err)
	}

	// PEM encode the TLS certificate
	certPEMBuf := new(bytes.Buffer)
	err = pem.Encode(certPEMBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		panic(err)
	}

	return certPEMBuf, certPrivKeyBuf
}
