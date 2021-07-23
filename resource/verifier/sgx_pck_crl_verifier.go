/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/pkg/errors"
	"intel/isecl/sqvs/v5/constants"
	"strings"
	"time"
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
	rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) (bool, error) {
	if len(crlList) == 0 || len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyPckCrl: CRL List/InterCA/RootCA is empty")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyPckCrl: Trusted CA Verification Failed")
	}

	for i := 0; i < len(interCA); i++ {
		_, err := verifyInterCaCert(interCA[i], rootCA, constants.SGXInterCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyPckCrl: verifyInterCaCert failed")
		}
	}
	for i := 0; i < len(rootCA); i++ {
		_, err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyPckCrl: verifyRootCaCert failed ")
		}
	}

	var signPassCount int
	for i := 0; i < len(crlList); i++ {
		ret := checkExpiry(crlList[i])
		if !ret {
			return false, errors.New("VerifyPckCrl: Revocation List has Expired" + crlURL[i])
		}
		ret = verifyPckCrlIssuer(crlList[i])
		if !ret {
			return false, errors.New("VerifyPckCrl: CRL Issuer info is Invalid: " + crlURL[i])
		}

		for j := 0; j < len(interCA); j++ {
			err := interCA[i].CheckCRLSignature(crlList[i])
			if err == nil {
				signPassCount++
			}
		}

		if signPassCount == 0 {
			return false, errors.New("VerifyPckCrl: Signature Verification failed")
		}
	}

	return true, nil
}
