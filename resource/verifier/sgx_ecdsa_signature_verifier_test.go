/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateHash(t *testing.T) {

	testValue := []byte("test")

	h := sha256.New()
	h.Write(testValue)
	expected := h.Sum(nil)

	got := generateHash(testValue)
	assert.Equal(t, expected, got)
}

func TestVerifyECDSA256Signature(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	msg := []byte("hello, world")
	hash := sha256.Sum256(msg)

	signatureBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	assert.Nil(t, err)

	publicKey := &privateKey.PublicKey

	got := verifyECDSA256Signature(msg, publicKey, signatureBytes)
	assert.Equal(t, false, got)
}

func TestVerifyQeReportSignature(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	msg := []byte("hello, world")
	hash := sha256.Sum256(msg)

	signatureBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	assert.Nil(t, err)

	publicKey := &privateKey.PublicKey

	err = VerifyQeReportSignature(signatureBytes, msg, publicKey)
	assert.NotNil(t, err)
}

func TestVerifyEnclaveReportSignature(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	msg := []byte("hello, world")
	hash := sha256.Sum256(msg)

	signatureBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	assert.Nil(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.Nil(t, err)
	publickeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	err = VerifyEnclaveReportSignature(signatureBytes, msg, pem.EncodeToMemory(publickeyPem))
	assert.NotNil(t, err)
}
