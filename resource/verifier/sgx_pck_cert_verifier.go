/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"intel/isecl/sqvs/v4/constants"
	"strings"

	"github.com/pkg/errors"
)

func VerifyPCKCertificate(pckCert *x509.Certificate, interCA, rootCA []*x509.Certificate,
	crl []*pkix.CertificateList, trustedRootCA *x509.Certificate) error {
	numInterCA := len(interCA)
	numRootCA := len(rootCA)
	numCrl := len(crl)

	if pckCert == nil || numInterCA == 0 || numRootCA == 0 || numCrl == 0 {
		return errors.New("VerifyPCKCertificate: Invalid Inter/Root ca certs, CRL data")
	}

	if !verifyCaSubject(pckCert.Subject.String(), constants.SGXPCKCertificateSubjectStr) {
		return errors.New("VerifyPCKCertificate: Invalid Subject info in PCK Certificate")
	}

	if !verifyCaSubject(pckCert.Issuer.String(), constants.SGXInterCACertSubjectStr) {
		return errors.New("VerifyPCKCertificate: Invalid Issuer info in PCK Certificate")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return errors.New("VerifyPCKCertificate: Trusted CA Verification Failed")
	}

	var opts x509.VerifyOptions
	opts.Intermediates = x509.NewCertPool()
	for i := 0; i < numInterCA; i++ {
		err := verifyInterCaCert(interCA[i], rootCA, constants.SGXInterCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "Invalid Intermediate CA Certificate")
		}
		opts.Intermediates.AddCert(interCA[i])
	}
	opts.Roots = x509.NewCertPool()
	for i := 0; i < numRootCA; i++ {
		err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "Invalid Root CA Certificate")
		}
		opts.Roots.AddCert(rootCA[i])
	}

	_, err := pckCert.Verify(opts)
	if err != nil {
		log.Error("Error during  PCK Certificate Verification:", err.Error())
		return errors.Wrap(err, "VerifyPCKCertificate: verify certificate")
	}

	for i := 0; i < numCrl; i++ {
		log.Debug("CRL Revoked Certificate Count:", len(crl[i].TBSCertList.RevokedCertificates))
		for _, crlObj := range crl[i].TBSCertList.RevokedCertificates {
			if pckCert.SerialNumber.Cmp(crlObj.SerialNumber) == 0 {
				log.Error("PCK Certificate is Revoked")
				return errors.New("VerifyPCKCertificate: PCK Certificate is Revoked")
			}
		}
	}
	return nil
}
