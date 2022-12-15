/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetMandatoryCertExtMap(t *testing.T) {
	got := getMandatoryCertExtMap()
	assert.NotNil(t, got)
}

func TestVerifyCaSubject(t *testing.T) {

	// test with empty string
	got := verifyCaSubject("", "")
	assert.Equal(t, false, got)

	// valid input is present
	got = verifyCaSubject("test", "test|hostname|commonname")
	assert.Equal(t, true, got)

	// valid input is not present
	got = verifyCaSubject("test", "hostname|commonname")
	assert.Equal(t, false, got)
}

func TestVerifySHA256Hash(t *testing.T) {
	hashValue := make([]byte, sha256.Size)

	// invalid hash
	err := VerifySHA256Hash(make([]byte, sha512.Size), []byte("test"))
	assert.NotNil(t, err)

	// hash verification failed
	err = VerifySHA256Hash(hashValue, []byte("test"))
	assert.NotNil(t, err)

	h := sha256.New()
	h.Write([]byte("test"))
	testHashValue := h.Sum(nil)

	// valid hash verification
	err = VerifySHA256Hash(testHashValue, []byte("test"))
	assert.Nil(t, err)
}

func TestCheckMandatorySGXExt(t *testing.T) {

	testCertificate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   "TEST COMMON NAME",
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		Extensions: []pkix.Extension{
			{},
		},
		BasicConstraintsValid: true,
	}

	// No extensions added in certificate
	err := CheckMandatorySGXExt(testCertificate, nil)
	assert.Nil(t, err)

	// var ExtSgxOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	extSgxOid := pkix.Extension{
		Id:       ExtSgxOid,
		Critical: true,
	}

	extCRLDistributionPointOid := pkix.Extension{
		Id:       ExtCRLDistributionPointOid,
		Critical: true,
	}

	extSubjectKebyIdentifierOid := pkix.Extension{
		Id:       ExtSubjectKeyIdentifierOid,
		Critical: true,
	}
	testCertificate.Extensions = append(testCertificate.Extensions, extCRLDistributionPointOid)
	testCertificate.Extensions = append(testCertificate.Extensions, extSubjectKebyIdentifierOid)
	testCertificate.Extensions = append(testCertificate.Extensions, extSgxOid)

	requiredExtDict := make(map[string]asn1.ObjectIdentifier)
	requiredExtDict[extCRLDistributionPointOid.Id.String()] = ExtCRLDistributionPointOid
	requiredExtDict[extSubjectKebyIdentifierOid.Id.String()] = ExtSubjectKeyIdentifierOid
	requiredExtDict[extSgxOid.Id.String()] = ExtSgxOid

	err = CheckMandatorySGXExt(testCertificate, requiredExtDict)
	assert.NotNil(t, err)
}

func TestVerifyRootCaCert(t *testing.T) {

	rootCA := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   "TEST COMMON NAME",
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		Issuer: pkix.Name{
			CommonName:   "TEST COMMON NAME",
			Organization: []string{"Intel Corporation"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
		},
		BasicConstraintsValid: true,
	}
	rootCA.Extensions = append(rootCA.Extensions, pkix.Extension{Id: ExtAuthorityKeyIdentifierOid, Critical: true})
	rootCA.Extensions = append(rootCA.Extensions, pkix.Extension{Id: ExtCRLDistributionPointOid, Critical: true})
	rootCA.Extensions = append(rootCA.Extensions, pkix.Extension{Id: ExtSubjectKeyIdentifierOid, Critical: true})
	rootCA.Extensions = append(rootCA.Extensions, pkix.Extension{Id: ExtKeyUsageOid, Critical: true})
	rootCA.Extensions = append(rootCA.Extensions, pkix.Extension{Id: ExtBasicConstrainsOid, Critical: true})

	err := verifyRootCaCert(rootCA, "CN=TEST COMMON NAME,O=Intel Corporation,L=Santa Clara,ST=CA,C=US")
	// "CN=Intel SGX PCK Certificate,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	assert.NotNil(t, err)

	err = verifyRootCaCert(rootCA, "TEST COMMON NAME")
	assert.NotNil(t, err)
}
