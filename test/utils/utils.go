package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	TestConfigFilePath    = "../test/config.yml"
	TrustedSGXRootCA      = "../trustedSGXRootCA.pem"
	IntermediateSGXRootCA = "../intermediateSGXRootCA.pem"
	PckCertFilePath       = "../pck-cert.pem"
)

func ReadCertFromFile(t *testing.T, certFilePath string) *x509.Certificate {
	trustedSGXRootCABytes, err := ioutil.ReadFile(certFilePath)
	assert.Nil(t, err)

	pemBlock, _ := pem.Decode(trustedSGXRootCABytes)
	assert.NotNil(t, pemBlock)

	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	assert.Nil(t, err)

	return x509Cert
}

func CreateTestCertificate(certFilePath, commonName string, caPrivateKey *ecdsa.PrivateKey, IsCA bool, rootCA *x509.Certificate) *x509.Certificate {

	tetstCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        IsCA,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		Extensions: []pkix.Extension{
			{},
		},
		BasicConstraintsValid: true,
	}

	if rootCA == nil {
		rootCA = tetstCert
	}

	// save certificate
	tetstCertBytes, err := x509.CreateCertificate(rand.Reader, tetstCert, rootCA, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}

	testCertPem := &pem.Block{Type: "CERTIFICATE", Bytes: tetstCertBytes}

	thisRootFileCA, err := os.OpenFile(certFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := thisRootFileCA.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(thisRootFileCA, testCertPem)
	if err != nil {
		log.Fatalf("I/O error while encoding private key file %v", err)
	}
	return tetstCert
}

func RemoveTestCert(certFilePath string) error {
	err := os.Remove(certFilePath)
	if err != nil {
		return err
	}
	return nil
}
