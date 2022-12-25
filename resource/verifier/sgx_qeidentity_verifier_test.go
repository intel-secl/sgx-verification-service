/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyQeIDCertChain(t *testing.T) {

	rootCA := createTestCert("Intel SGX Root CA", true, nil)
	intermediateCA := createTestCert("Intel SGX TCB Signing", true, nil)

	intermediateCA.Extensions = append(intermediateCA.Extensions, pkix.Extension{Id: ExtAuthorityKeyIdentifierOid, Critical: true})
	intermediateCA.Extensions = append(intermediateCA.Extensions, pkix.Extension{Id: ExtCRLDistributionPointOid, Critical: true})
	intermediateCA.Extensions = append(intermediateCA.Extensions, pkix.Extension{Id: ExtSubjectKeyIdentifierOid, Critical: true})
	intermediateCA.Extensions = append(intermediateCA.Extensions, pkix.Extension{Id: ExtKeyUsageOid, Critical: true})
	intermediateCA.Extensions = append(intermediateCA.Extensions, pkix.Extension{Id: ExtBasicConstrainsOid, Critical: true})

	err := VerifyQeIDCertChain(nil, nil, rootCA)
	assert.NotNil(t, err)

	err = VerifyQeIDCertChain([]*x509.Certificate{intermediateCA}, []*x509.Certificate{rootCA}, rootCA)
	assert.NotNil(t, err)
}

func TestVerifyReportAttrSize(t *testing.T) {
	qeAttribute := [HashSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	err := VerifyReportAttrSize(qeAttribute, "attributeName", "attribute")
	assert.NotNil(t, err)

	err = VerifyReportAttrSize(qeAttribute, "attributeName", hex.EncodeToString(qeAttribute[:]))
	assert.Nil(t, err)

	err = VerifyReportAttrSize(qeAttribute, "attributeName", hex.EncodeToString([]byte("testBytes")))
	assert.Nil(t, err)
}

func TestVerifyMiscSelect(t *testing.T) {

	err := VerifyMiscSelect(2, "miscSelect", hex.EncodeToString([]byte("testvalues")))
	assert.NotNil(t, err)

	err = VerifyMiscSelect(2, hex.EncodeToString([]byte("miscSelect")), hex.EncodeToString([]byte("testvalues")))
	assert.NotNil(t, err)

	err = VerifyMiscSelect(2, hex.EncodeToString([]byte("miscSelect")), "testvalues")
	assert.NotNil(t, err)
}

func TestVerifyAttributes(t *testing.T) {
	reportAttribute := [AttributeSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	err := VerifyAttributes(reportAttribute, "qeAttributes", hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	assert.NotNil(t, err)

	err = VerifyAttributes(reportAttribute, hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	assert.Nil(t, err)

	err = VerifyAttributes(reportAttribute, hex.EncodeToString([]byte("qeAttributes")), hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	assert.NotNil(t, err)

	err = VerifyAttributes(reportAttribute, hex.EncodeToString([]byte("qeAttributes")), "qeAttributes")
	assert.NotNil(t, err)
}
