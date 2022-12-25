/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"intel/isecl/lib/common/v5/crypt"
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/constants"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
		Flags:                    []string{"-port=12000"},
		Config:                   &c,
		ConsoleWriter:            os.Stdout,
		TrustedSGXRootCAFilePath: rootCACertFile,
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
	if err != nil {
		assert.Contains(t, err.Error(), config.ErrNoConfigFile.Error())
	}
	assert.Equal(t, 12000, c.Port)

	err = s.Validate(ctx)
	assert.Equal(t, err, nil)
}

func TestServerSetupEnv(t *testing.T) {

	os.Setenv("AAS_API_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	os.Setenv("SQVS_PORT", "12000")
	defer os.Clearenv()

	c := config.Configuration{}

	s := Update_Service_Config{
		Flags:                    nil,
		Config:                   &c,
		ConsoleWriter:            os.Stdout,
		TrustedSGXRootCAFilePath: rootCACertFile,
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
	if err != nil {
		assert.Contains(t, err.Error(), config.ErrNoConfigFile.Error())
	}
	assert.Equal(t, 12000, c.Port)
}

func TestServerSetupInvalidAASUrl(t *testing.T) {
	os.Setenv("AAS_API_URL", "invalidurl")
	os.Setenv("SCS_BASE_URL", "http://localhost:12000/scs/v1")
	defer os.Clearenv()

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "AAS_API_URL provided is invalid"))
}

func TestServerSetupInvalidScsBaseUrlArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_BASE_URL", "abcdefg")
	defer os.Clearenv()

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "SCS_BASE_URL provided is invalid"))
	assert.Equal(t, constants.DefaultHTTPSPort, c.Port)
}

func TestServerSetupInvalidLogLevelArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_BASE_URL", "http://localhost:12000/scs/v1")
	os.Setenv("SQVS_LOGLEVEL", "invalidloglevel")
	defer os.Clearenv()

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:                    nil,
		Config:                   &c,
		ConsoleWriter:            os.Stdout,
		TrustedSGXRootCAFilePath: rootCACertFile,
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
	s.Config.SaveConfiguration("update_service_config", ctx)
	err = s.Run(ctx)
	assert.NoError(t, err)
	assert.Equal(t, logrus.InfoLevel, c.LogLevel)
}

func TestServerSetupRootCertFailure(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_BASE_URL", "http://localhost:12000/scs/v1")
	os.Setenv("SQVS_LOGLEVEL", "invalidloglevel")
	defer os.Clearenv()

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

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
	s.Config.SaveConfiguration("update_service_config", ctx)
	err = s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "Error writing SGX root cert to file"))
	assert.Equal(t, logrus.InfoLevel, c.LogLevel)
}

func TestServerSetupNegativeCases(t *testing.T) {

	err := testGetRootCACert()
	if err != nil {
		t.Error("Cert generation failed")
	}
	defer func() {
		_ = os.Remove(rootCACertFile)
	}()
	_ = os.Setenv("SGX_TRUSTED_ROOT_CA_PATH", rootCACertFile)

	os.Setenv("AAS_API_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	os.Setenv("SQVS_PORT", "1000")
	defer os.Clearenv()

	c1 := config.Configuration{
		Port: 1000,
	}

	s1 := Update_Service_Config{
		Flags:                    []string{"test"},
		Config:                   &c1,
		ConsoleWriter:            os.Stdout,
		TrustedSGXRootCAFilePath: rootCACertFile,
	}
	ctx := setup.Context{}
	err = s1.Run(ctx)
	assert.Equal(t, err, nil)

	c := config.Configuration{
		Port: 12000,
	}

	s := Update_Service_Config{
		Flags:                    []string{"test"},
		Config:                   &c,
		ConsoleWriter:            os.Stdout,
		TrustedSGXRootCAFilePath: rootCACertFile,
	}

	os.Setenv("SQVS_PORT", "12000")
	os.Setenv("SQVS_SERVER_READ_TIMEOUT", "testValue")
	os.Setenv("SQVS_SERVER_READ_HEADER_TIMEOUT", "testValue")
	os.Setenv("SQVS_SERVER_WRITE_TIMEOUT", "testValue")
	os.Setenv("SQVS_SERVER_IDLE_TIMEOUT", "testValue")
	os.Setenv("SQVS_SERVER_MAX_HEADER_BYTES", "testValue")
	os.Setenv("SQVS_LOGLEVEL", "testValue")
	os.Setenv("SQVS_LOG_MAX_LENGTH", "testValue")
	os.Setenv("SQVS_ENABLE_CONSOLE_LOG", "testValue")
	os.Setenv("SQVS_INCLUDE_TOKEN", "testValue")
	os.Setenv("SCS_BASE_URL", "testValue")
	os.Setenv("AAS_API_URL", "testValue")

	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	os.Setenv("SQVS_SERVER_MAX_HEADER_BYTES", "1000000")
	os.Setenv("SQVS_LOGLEVEL", "info")
	os.Setenv("SQVS_LOG_MAX_LENGTH", "400")
	os.Setenv("SCS_BASE_URL", "")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	os.Setenv("SCS_BASE_URL", "https://scs.com/v1/scs/")
	os.Setenv("AAS_API_URL", "https://aas.com/v1/aas/")
	os.Setenv("RESPONSE_SIGNING_KEY_LENGTH", "4096")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	os.Setenv("SCS_BASE_URL", "https://scs.com/v1/scs/")
	os.Unsetenv("AAS_API_URL")
	c.AuthServiceURL = ""
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	c.AuthServiceURL = "https://aas.com/v1/aas/"
	// Invalid SIGN_QUOTE_RESPONSE
	os.Setenv("SIGN_QUOTE_RESPONSE", "testvalue")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Invalid RESPONSE_SIGNING_KEY_LENGTH
	os.Setenv("RESPONSE_SIGNING_KEY_LENGTH", "15360")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Invalid USE_PSS_PADDING
	os.Setenv("USE_PSS_PADDING", "testvalue")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

}
