/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (

	"errors"
       	"math/big"
       	"crypto/ecdsa"
       	"crypto/sha256"
       	"crypto/elliptic"

	log "github.com/sirupsen/logrus"

       	"intel/isecl/svs/resource/utils"
)

type ECDSASignature struct {
    R, S *big.Int
}

func GenerateHash(b []byte) []byte {
    h := sha256.New()
    h.Write(b)
    return h.Sum(nil)
}

func VerifyECDSA256Signature( data []byte, pubkey *ecdsa.PublicKey, signatureBytes []byte) (bool){

	var signature ECDSASignature
	rBytes, sBytes 	:= signatureBytes[:32], signatureBytes[32:]

    	signature.R 	= new(big.Int).SetBytes(rBytes)
    	signature.S 	= new(big.Int).SetBytes(sBytes) 

	h 		:= GenerateHash(data)	
	valid 		:= ecdsa.Verify(
						pubkey,
						h,
						signature.R,
						signature.S,
    			   )

	utils.DumpDataInHex("VerifyEcdsa256Signature-Data", data, len(data))
	utils.DumpDataInHex("VerifyEcdsa256Signature-Signature", signatureBytes, len(signatureBytes))

	if valid {
		log.Debug("Signature Verification is Passed")
	}else {
		log.Debug("Signature Verification is Failed")
	}
	return valid
}

func VerifySGXECDSASignature1(sigBlob []byte, blob []byte, pubKey *ecdsa.PublicKey) (bool, error){
	if len(sigBlob) < 1 || len(blob) < 1  || pubKey == nil {
		return false, errors.New("SGXECDSASignature1: Invalid input data\n")
	}
	ret := VerifyECDSA256Signature(blob, pubKey, sigBlob)
	if !ret {
		return false, errors.New("ECDSA Signature Verification(1) is Failed")
	}
	return true, nil
}



func VerifySGXECDSASignature2(sigBlob []byte, blob []byte, pubKeyBlob []byte) (bool, error){
	if len(sigBlob) < 1 || len(blob) < 1  || len(pubKeyBlob) < 1 {
		return false, errors.New("SGXECDSASignature2: Invalid input data\n")
	}

	curve := elliptic.P256()
    	keyLen := len(pubKeyBlob)

    	x := big.Int{}
    	y := big.Int{}
    	x.SetBytes(pubKeyBlob[:(keyLen / 2)])
    	y.SetBytes(pubKeyBlob[(keyLen / 2):])

    	pubKey := ecdsa.PublicKey{curve, &x, &y}
	ret := VerifyECDSA256Signature(blob, &pubKey, sigBlob)
	if !ret {
		return false, errors.New("ECDSA Signature Verification(2) is Failed")
	}
	return true, nil
}
