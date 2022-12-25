/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	privatekeyLocation      = "../../test/privkey.pem"
	pkcs1PrivatekeyLocation = "../../test/testpkcs1privatekey.pem"
)

func TestGetCertPemData(t *testing.T) {
	// Test certificate.

	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	got, err := GetCertPemData(testCert)
	assert.Nil(t, err, nil)
	assert.NotNil(t, got, nil)

	// Test with NIL cert info.
	got, err = GetCertPemData(nil)
	assert.NotNil(t, err, nil)
	assert.Nil(t, got, nil)

}

func TestIntToBool(t *testing.T) {
	got := IntToBool(0)
	assert.Equal(t, false, got)

	got = IntToBool(1)
	assert.Equal(t, true, got)
}

func TestCheckDate(t *testing.T) {

	// valid dates given.
	issueDate := time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
	nextUpdate := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	got := CheckDate(issueDate, nextUpdate)

	assert.Equal(t, true, got)

	// Different time format.
	issueDate = time.Now().Add(-10 * time.Minute).Format(time.RFC1123)
	nextUpdate = time.Now().Add(10 * time.Hour).Format(time.RFC1123)
	got = CheckDate(issueDate, nextUpdate)
	assert.Equal(t, false, got)

	issueDate = time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
	nextUpdate = time.Now().Add(10 * time.Hour).Format(time.RFC1123)
	got = CheckDate(issueDate, nextUpdate)
	assert.Equal(t, false, got)

	// Invalid issue date and next update date.
	issueDate = time.Now().Add(10 * time.Hour).Format(time.RFC3339)
	nextUpdate = time.Now().Add(-10 * time.Hour).Format(time.RFC3339)
	got = CheckDate(issueDate, nextUpdate)

	assert.Equal(t, false, got)
}

func TestGenerateSignature(t *testing.T) {

	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(keyPair)
	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFile, err := os.OpenFile(privatekeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := privateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		log.Fatalf("I/O error while encoding private key file %v", err)
	}

	// PKCS1 format

	// save private key
	pkcs1Key := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	pkcs1KeyFile, err := os.OpenFile(pkcs1PrivatekeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := pkcs1KeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(pkcs1KeyFile, pkcs1Key)
	if err != nil {
		log.Fatalf("I/O error while encoding private key file %v", err)
	}

	// test without PSS padding
	_, err = GenerateSignature([]byte("testbytes"), privatekeyLocation, false)
	assert.Nil(t, err, nil)

	// test with PSS padding
	_, err = GenerateSignature([]byte("testbytes"), privatekeyLocation, true)
	assert.Nil(t, err, nil)

	// test with empty keyfile name
	_, err = GenerateSignature([]byte("testbytes"), "", true)
	assert.NotNil(t, err, nil)

	// test with pkcs1 Privatekey
	_, err = GenerateSignature([]byte("testbytes"), pkcs1PrivatekeyLocation, true)
	assert.NotNil(t, err, nil)

	// remove test files at the end.
	os.Remove(privatekeyLocation)
	os.Remove(pkcs1PrivatekeyLocation)
}

func TestGetCertObjList(t *testing.T) {

	testSGXPCKCertificateIssuerChain := `-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAkCgAwIBAgIUWSPTp0qoY1QuOXCt4A8HK1ckKrcwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE5MTAzMTEyMzM0N1oXDTM0MTAzMTEyMzM0N1owcDEiMCAG%0AA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwg%0AQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEL%0AMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQwp%2BLc%2BTUBtg1H%0A%2BU8JIsMsbjHjCkTtXb8jPM6r2dhu9zIblhDZ7INfqt3Ix8XcFKD8k0NEXrkZ66qJ%0AXa1KzLIKo4G%2FMIG8MB8GA1UdIwQYMBaAFOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMFYG%0AA1UdHwRPME0wS6BJoEeGRWh0dHBzOi8vc2J4LWNlcnRpZmljYXRlcy50cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQU%0AWSPTp0qoY1QuOXCt4A8HK1ckKrcwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQI%0AMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1q%2BFTz%2BgUuVfBQuCgJsFrL2TTS%0Ae1aBZ53O52TjFie6AiAriPaRahUX9Oa9kGLlAchWXKT6j4RWSR50BqhrN3UT4A%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIClDCCAjmgAwIBAgIVAOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xOTEwMzEwOTQ5MjFaFw00OTEyMzEyMzU5NTlaMGgxGjAY%0ABgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3Jh%0AdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQG%0AEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE%2F6D%2F1WHNrWwPmNMIyBKMW5%0AJ6JzMsjo6xP2vkK1cdZGb1PGRP%2FC%2F8ECgiDkmklmzwLzLi%2B000m7LLrtKJA3oC2j%0Agb8wgbwwHwYDVR0jBBgwFoAU6ehEUlM2XEsYmhH8QxgspdwggEgwVgYDVR0fBE8w%0ATTBLoEmgR4ZFaHR0cHM6Ly9zYngtY2VydGlmaWNhdGVzLnRydXN0ZWRzZXJ2aWNl%0Acy5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuZGVyMB0GA1UdDgQWBBTp6ERSUzZc%0ASxiaEfxDGCyl3CCASDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH%2FBAgwBgEB%2FwIB%0AATAKBggqhkjOPQQDAgNJADBGAiEAzw9zdUiUHPMUd0C4mx41jlFZkrM3y5f1lgnV%0AO7FbjOoCIQCoGtUmT4cXt7V%2BySHbJ8Hob9AanpvXNH1ER%2B%2FgZF%2BopQ%3D%3D%0A-----END%20CERTIFICATE-----%0A`
	_, err := GetCertObjList(testSGXPCKCertificateIssuerChain)
	assert.Nil(t, err, nil)
}
