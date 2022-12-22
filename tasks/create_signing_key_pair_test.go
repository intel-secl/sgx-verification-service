/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/sqvs/v5/config"
	"log"
	random "math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	privatekeyLocation      = "../test/testprivatekey.pem"
	pkcs1PrivatekeyLocation = "../test/testpkcs1privatekey.pem"
	publicKeyLocation       = "../test/testpublickey.pem"
)

func createRSAKeyFiles() {
	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	publicKey := &keyPair.PublicKey

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(keyPair)
	if err != nil {
		log.Fatalf("Failed to parse private key bytes %v", err)
	}

	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key bytes %v", err)
	}
	publickeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
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

	pubKeyFile, err := os.OpenFile(publicKeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving public key file %v", err)
	}
	defer func() {
		derr := pubKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(pubKeyFile, publickeyPem)
	if err != nil {
		log.Fatalf("I/O error while encoding public key file %v", err)
	}
}

func TestCreateSigningKeyPairValidate(t *testing.T) {

	createRSAKeyFiles()
	defer func() {
		os.Remove(privatekeyLocation)
		os.Remove(publicKeyLocation)
		os.Remove(pkcs1PrivatekeyLocation)
	}()

	// write global configuration manually and write it to file. Then Load the same using Load()
	ctx := setup.Context{}
	conf := &config.Configuration{
		Port:             1337,
		CmsTLSCertDigest: RandStringBytes(),
		CMSBaseURL:       "https://cms.com/v1/cms/",
		AuthServiceURL:   "https://aas.com/v1/aas/",
		SCSBaseURL:       "https://scs.com/v1/scs/",
		Subject: struct{ TLSCertCommonName string }{
			TLSCertCommonName: "TEST COMMON NAME",
		},
	}

	testKeyPair := Create_Signing_Key_Pair{
		Flags:              []string{"ca"},
		Config:             conf,
		ConsoleWriter:      os.Stdout,
		PrivateKeyLocation: privatekeyLocation,
		PublicKeyLocation:  publicKeyLocation,
		TrustedCAsStoreDir: "../test/",
	}

	err := testKeyPair.Run(ctx)
	assert.Equal(t, err, nil)

	os.Setenv("BEARER_TOKEN", RandStringBytes())
	err = testKeyPair.Run(ctx)
	assert.Equal(t, err, nil)

	// Invalid PrivateKey location
	testKeyPair = Create_Signing_Key_Pair{
		Flags:              []string{"ca"},
		Config:             conf,
		ConsoleWriter:      os.Stdout,
		PrivateKeyLocation: "/test/key/location",
		PublicKeyLocation:  publicKeyLocation,
		TrustedCAsStoreDir: "../test/",
	}
	err = testKeyPair.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Invalid PrivateKey Format
	testKeyPair = Create_Signing_Key_Pair{
		Flags:              []string{"ca"},
		Config:             conf,
		ConsoleWriter:      os.Stdout,
		PrivateKeyLocation: pkcs1PrivatekeyLocation,
		PublicKeyLocation:  publicKeyLocation,
		TrustedCAsStoreDir: "../test/",
	}
	err = testKeyPair.Run(ctx)
	assert.Equal(t, err, nil)

	// Invalid PublicKey location
	testKeyPair = Create_Signing_Key_Pair{
		Flags:              []string{"ca"},
		Config:             conf,
		ConsoleWriter:      os.Stdout,
		PrivateKeyLocation: privatekeyLocation,
		PublicKeyLocation:  "/test/key/location",
		TrustedCAsStoreDir: "../test/",
	}
	err = testKeyPair.Run(ctx)
	assert.NotEqual(t, err, nil)

}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes() string {
	random.Seed(time.Now().UnixNano())
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[random.Intn(len(letterBytes))]
	}
	return string(b)
}
