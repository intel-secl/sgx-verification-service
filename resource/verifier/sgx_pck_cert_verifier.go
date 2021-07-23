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
)

func VerifyPCKCertificate(pckCert *x509.Certificate, interCA, rootCA []*x509.Certificate,
	crl []*pkix.CertificateList, trustedRootCA *x509.Certificate) (bool, error) {
	if pckCert == nil || len(interCA) == 0 || len(rootCA) == 0 || len(crl) == 0 {
		return false, errors.New("VerifyPCKCertificate: Invalid Inter/Root ca certs, CRL data")
	}

	if !verifyCaSubject(pckCert.Subject.String(), constants.SGXPCKCertificateSubjectStr) {
		return false, errors.New("VerifyPCKCertificate: Invalid Subject info in PCK Certificate")
	}

	if !verifyCaSubject(pckCert.Issuer.String(), constants.SGXInterCACertSubjectStr) {
		return false, errors.New("VerifyPCKCertificate: Invalid Issuer info in PCK Certificate")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyPCKCertificate: Trusted CA Verification Failed")
	}

	var opts x509.VerifyOptions
	opts.Intermediates = x509.NewCertPool()
	for i := 0; i < len(interCA); i++ {
		_, err := verifyInterCaCert(interCA[i], rootCA, constants.SGXInterCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "Invalid Inter CA Certificate")
		}
		opts.Intermediates.AddCert(interCA[i])
	}
	opts.Roots = x509.NewCertPool()
	for i := 0; i < len(rootCA); i++ {
		_, err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "Invalid Root CA Certificate")
		}
		opts.Roots.AddCert(rootCA[i])
	}

	_, err := pckCert.Verify(opts)
	if err != nil {
		log.Error("Error during  PCK Certificate Verification:", err.Error())
		return false, errors.Wrap(err, "VerifyPCKCertificate: verify certificate")
	}

	for i := 0; i < len(crl); i++ {
		log.Debug("CRL Revoked Certificate Count:", len(crl[i].TBSCertList.RevokedCertificates))
		for _, crlObj := range crl[i].TBSCertList.RevokedCertificates {
			if pckCert.SerialNumber.Cmp(crlObj.SerialNumber) == 0 {
				log.Error("PCK Certificate is Revoked")
				return false, errors.New("VerifyPCKCertificate: PCK Certificate is Revoked")
			}
		}
	}
	return true, nil
}
