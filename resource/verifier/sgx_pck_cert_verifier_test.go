/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testConfigFilePath    = "../../test/config.yml"
	trustedSGXRootCA      = "../../test/trustedSGXRootCA.pem"
	intermediateSGXRootCA = "../../test/intermediateSGXRootCA.pem"
	pckCertFilePath       = "../../test/pck-cert.pem"
)

func readCertFromFile(t *testing.T, certFilePath string) *x509.Certificate {
	trustedSGXRootCABytes, err := ioutil.ReadFile(certFilePath)
	assert.Nil(t, err)

	pemBlock, _ := pem.Decode(trustedSGXRootCABytes)
	assert.NotNil(t, pemBlock)

	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	assert.Nil(t, err)

	return x509Cert
}

func createTestCert(commonName string, IsCA bool, rootCA *x509.Certificate) *x509.Certificate {

	tetstCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  IsCA,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	if commonName == "Intel SGX PCK Certificate" {
		tetstCert.Issuer = pkix.Name{
			CommonName:   "Intel SGX PCK Processor CA",
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		}
	}
	return tetstCert
}

func TestVerifyPCKCertificate(t *testing.T) {

	err := VerifyPCKCertificate(nil, nil, nil, nil, nil)
	assert.NotNil(t, err)

	rootCA := createTestCert("Intel SGX Root CA", true, nil)
	intermediateCA := createTestCert("Intel SGX PCK Processor CA", true, nil)
	pckCert := createTestCert("Intel SGX PCK Certificate", false, intermediateCA)

	crl := &pkix.CertificateList{
		TBSCertList: pkix.TBSCertificateList{
			NextUpdate: time.Now().Add(1 * time.Hour),
		},
	}

	err = VerifyPCKCertificate(pckCert, []*x509.Certificate{rootCA}, []*x509.Certificate{intermediateCA}, []*pkix.CertificateList{crl}, rootCA)
	assert.NotNil(t, err)

	pckCert = createTestCert("Intel SGX PCK Certificate Test", false, intermediateCA)
	err = VerifyPCKCertificate(pckCert, []*x509.Certificate{rootCA}, []*x509.Certificate{intermediateCA}, []*pkix.CertificateList{crl}, rootCA)
	assert.NotNil(t, err)
}
