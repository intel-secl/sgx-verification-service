/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"intel/isecl/sqvs/v5/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	// create intermediate certificate and rootca.
	keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Errorf("Failed to create keypair")
	}

	utils.CreateTestCertificate(trustedSGXRootCA, "Intel SGX Root CA", keypair, true, nil)
	intermediateCA := utils.CreateTestCertificate(intermediateSGXRootCA, "Intel SGX PCK Processor CA", keypair, true, nil)
	utils.CreateTestCertificate(pckCertFilePath, "Intel SGX PCK Certificate", keypair, false, intermediateCA)

	generateRSAKeyPairs()
}

func generateRSAKeyPairs() {
	keypair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	privKeyBytes, _ := x509.MarshalPKCS8PrivateKey(keypair)
	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	privateKeyFile, err := os.OpenFile(privateKeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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

	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&keypair.PublicKey)
	// save public key
	pubKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	pubKeyFile, err := os.OpenFile(pubKeyLocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving public key file %v", err)
	}
	defer func() {
		derr := pubKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(pubKeyFile, pubKey)
	if err != nil {
		log.Fatalf("I/O error while encoding public key file %v", err)
	}
}

func TestResource(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resource Suite")

	defer func() {
		utils.RemoveTestCert(trustedSGXRootCA)
		utils.RemoveTestCert(intermediateSGXRootCA)
		utils.RemoveTestCert(pckCertFilePath)

		os.Remove(privateKeyLocation)
		os.Remove(pubKeyLocation)
	}()
}
