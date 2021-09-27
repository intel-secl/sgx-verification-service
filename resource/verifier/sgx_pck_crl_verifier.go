/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"intel/isecl/sqvs/v5/constants"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func checkExpiry(crl *pkix.CertificateList) bool {
	if crl.HasExpired(time.Now()) {
		log.Error("Certificate Revocation List Has Expired")
		return false
	}
	return true
}

func verifyPckCrlIssuer(crl *pkix.CertificateList) bool {
	issuer := crl.TBSCertList.Issuer.String()
	return verifyCaSubject(issuer, constants.SGXCRLIssuerStr)
}

func VerifyPckCrl(crlURL []string, crlList []*pkix.CertificateList, interCA,
	rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) error {
	numInterCA := len(interCA)
	numRootCA := len(rootCA)
	numCrlList := len(crlList)

	if numCrlList == 0 || numInterCA == 0 || numRootCA == 0 {
		return errors.New("VerifyPckCrl: CRL List/InterCA/RootCA is empty")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return errors.New("VerifyPckCrl: Trusted CA Verification Failed")
	}

	for i := 0; i < numInterCA; i++ {
		err := verifyInterCaCert(interCA[i], rootCA, constants.SGXInterCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyPckCrl: verifyInterCaCert failed")
		}
	}

	for i := 0; i < numRootCA; i++ {
		err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyPckCrl: verifyRootCaCert failed ")
		}
	}

	for i := 0; i < numCrlList; i++ {
		ret := checkExpiry(crlList[i])
		if !ret {
			return errors.New("VerifyPckCrl: Revocation List has Expired" + crlURL[i])
		}
		ret = verifyPckCrlIssuer(crlList[i])
		if !ret {
			return errors.New("VerifyPckCrl: CRL Issuer info is Invalid: " + crlURL[i])
		}

		for j := 0; j < numInterCA; j++ {
			err := interCA[i].CheckCRLSignature(crlList[i])
			if err != nil {
				return errors.New("VerifyPckCrl: Signature Verification failed")
			}
		}
	}
	return nil
}
