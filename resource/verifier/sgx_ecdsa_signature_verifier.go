/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/pkg/errors"
)

type ECDSASignature struct {
	R, S *big.Int
}

func generateHash(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func verifyECDSA256Signature(data []byte, pubkey *ecdsa.PublicKey, signatureBytes []byte) bool {
	var signature ECDSASignature
	rBytes, sBytes := signatureBytes[:32], signatureBytes[32:]

	signature.R = new(big.Int).SetBytes(rBytes)
	signature.S = new(big.Int).SetBytes(sBytes)

	h := generateHash(data)
	return ecdsa.Verify(pubkey, h, signature.R, signature.S)
}

func VerifyQeReportSignature(sigBlob, blob []byte, pckPubKey *ecdsa.PublicKey) error {
	ret := verifyECDSA256Signature(blob, pckPubKey, sigBlob)
	if !ret {
		return errors.New("QE Report Signature Verification Failed")
	}
	return nil
}

func VerifyEnclaveReportSignature(sigBlob, blob, attestPubKeyBlob []byte) error {
	curve := elliptic.P256()
	keyLen := len(attestPubKeyBlob)

	x := big.Int{}
	y := big.Int{}
	x.SetBytes(attestPubKeyBlob[:(keyLen / 2)])
	y.SetBytes(attestPubKeyBlob[(keyLen / 2):])

	attestPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	ret := verifyECDSA256Signature(blob, &attestPubKey, sigBlob)
	if !ret {
		return errors.New("Enclave Report Signature Verification Failed")
	}
	return nil
}
