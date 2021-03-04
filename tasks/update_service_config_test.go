/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v3/crypt"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/sqvs/v3/config"
	"math/big"
	"os"
	"testing"
	"time"
)

const (
	rootCACertFile  = "myrootcafile.pem"
	certSubjectName = "ISecl Self Sign Cert"
	certExpiryDays  = 180
	keyLength       = 3072
)

func testGetRootCACert() error {
	rsaKeyPair, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization: []string{certSubjectName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * certExpiryDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKeyPair.PublicKey, rsaKeyPair)
	if err != nil {
		return err
	}

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = crypt.SavePemCert(derBytes, rootCACertFile)
	if err != nil {
		return err
	}
	return nil
}

func TestServerSetup(t *testing.T) {
	c := config.Configuration{
		AuthServiceURL: "https://localhost",
		SCSBaseURL:     "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=12000"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	err := testGetRootCACert()
	if err != nil {
		t.Error("Cert generation failed")
	}
	defer func() {
		_ = os.Remove(rootCACertFile)
	}()
	_ = os.Setenv("SGX_TRUSTED_ROOT_CA_PATH", rootCACertFile)

	ctx := setup.Context{}
	_ = s.Run(ctx)
	//assert.Equal(t, config.ErrNoConfigFile, err)
	assert.Equal(t, 12000, c.Port)
}

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("AAS_API_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")

	os.Setenv("SQVS_PORT", "12000")
	c := config.Configuration{}

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}

	err := testGetRootCACert()
	if err != nil {
		t.Error("Cert generation failed")
	}
	defer func() {
		_ = os.Remove(rootCACertFile)
	}()
	_ = os.Setenv("SGX_TRUSTED_ROOT_CA_PATH", rootCACertFile)

	ctx := setup.Context{}
	err = s.Run(ctx)
	assert.Contains(t, err.Error(), config.ErrNoConfigFile.Error())
	assert.Equal(t, 12000, c.Port)
}
