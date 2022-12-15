/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"intel/isecl/sqvs/v5/test/utils"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	rootCALocation    = "../../test/rootca.pem"
	trustedCALocation = "../../test/trusted.pem"
	interCALocation   = "../../test/interca.pem"
)

func TestVerifyTcbInfoCertChain(t *testing.T) {

	var interCA []*x509.Certificate
	var rootCA []*x509.Certificate
	var trustedRootCA *x509.Certificate

	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	utils.CreateTestCertificate(interCALocation, "Intel SGX TCB Signing", caPrivateKey, true, nil)
	thisInterCA := utils.ReadCertFromFile(t, interCALocation)
	interCA = append(interCA, thisInterCA)

	utils.CreateTestCertificate(rootCALocation, "Intel SGX TCB Signing", caPrivateKey, true, nil)
	thisRootCA := utils.ReadCertFromFile(t, rootCALocation)
	rootCA = append(rootCA, thisRootCA)

	trustedRootCA = thisRootCA

	// NIL certificate info given.
	err = VerifyTcbInfoCertChain(nil, nil, nil)
	assert.NotNil(t, err)

	err = VerifyTcbInfoCertChain(rootCA, rootCA, trustedRootCA)
	assert.NotNil(t, err)

	err = VerifyTcbInfoCertChain(interCA, rootCA, trustedRootCA)
	assert.NotNil(t, err)

	// remove test files at the end.
	os.Remove(interCALocation)
	os.Remove(rootCALocation)
	os.Remove(trustedCALocation)
}
