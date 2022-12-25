/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckExpiry(t *testing.T) {
	// valid nextupdate time
	crl := &pkix.CertificateList{
		TBSCertList: pkix.TBSCertificateList{
			NextUpdate: time.Now().Add(1 * time.Hour),
		},
	}
	got := checkExpiry(crl)
	assert.Equal(t, true, got)

	// expired nextupdate time
	crl = &pkix.CertificateList{
		TBSCertList: pkix.TBSCertificateList{
			NextUpdate: time.Now().Add(-1 * time.Hour),
		},
	}
	got = checkExpiry(crl)
	assert.Equal(t, false, got)
}

func TestVerifyPckCrlIssuer(t *testing.T) {

	intermediateCA := createTestCert("Intel SGX PCK Processor CA", true, nil)
	pckCert := createTestCert("Intel SGX PCK Certificate", false, intermediateCA)

	crl := &pkix.CertificateList{
		TBSCertList: pkix.TBSCertificateList{
			Issuer:     pckCert.Issuer.ToRDNSequence(),
			NextUpdate: time.Now().Add(1 * time.Hour),
		},
	}
	ok := verifyPckCrlIssuer(crl)
	assert.Equal(t, false, ok)
}

func TestVerifyPckCrl(t *testing.T) {

	crlURL := []string{"http://test.com/"}
	err := VerifyPckCrl(nil, nil, nil, nil, nil)
	assert.NotNil(t, err)

	rootCA := createTestCert("Intel SGX Root CA", true, nil)
	intermediateCA := createTestCert("Intel SGX PCK Processor CA", true, nil)

	crl := &pkix.CertificateList{
		TBSCertList: pkix.TBSCertificateList{
			NextUpdate: time.Now().Add(1 * time.Hour),
		},
	}

	err = VerifyPckCrl(crlURL, []*pkix.CertificateList{crl}, []*x509.Certificate{intermediateCA}, []*x509.Certificate{rootCA}, rootCA)
	assert.NotNil(t, err)

	err = VerifyPckCrl(crlURL, []*pkix.CertificateList{crl}, []*x509.Certificate{intermediateCA}, []*x509.Certificate{rootCA}, rootCA)
	assert.NotNil(t, err)
}
