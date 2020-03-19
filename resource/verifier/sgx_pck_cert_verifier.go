/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"strings"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/pkg/errors"
	"intel/isecl/svs/constants"
)


func VerifyPCKCertificate(pckCert *x509.Certificate, interCA []*x509.Certificate, RootCA []*x509.Certificate,
					crl []*pkix.CertificateList, trustedRootCA *x509.Certificate) (bool, error){
	log.Trace("resource/verifier/sgx_pck_cert_verifier:VerifyPCKCertificate() Entering")
	defer log.Trace("resource/verifier/sgx_pck_cert_verifier:VerifyPCKCertificate() Leaving")

	if pckCert == nil || len(interCA) == 0 || len(RootCA) == 0 || len(crl)==0 {
		return false, errors.New("VerifyPCKCertificate: Invalid Inter/Root ca certs, CRL data")
	}

	if !VerifyString( pckCert.Subject.String(), constants.SGXPCKCertificateSubjectStr){
		return false, errors.New("VerifyPCKCertificate: Invalid Subject info in PCK Certicate")
	}

	if !VerifyString( pckCert.Issuer.String(), constants.SGXInterCACertSubjectStr){
		return false, errors.New("VerifyPCKCertificate: Invalid Issuer info in PCK Certicate")
	}

	var opts x509.VerifyOptions
	opts.Intermediates = x509.NewCertPool()
	for i:=0; i<len(interCA);i++ {
		_, err := VerifyInterCACertificate( interCA[i], RootCA, constants.SGXInterCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "Invalid Inter CA Certificate")
		}
		opts.Intermediates.AddCert(interCA[i])
	}
	opts.Roots = x509.NewCertPool()
	for i:=0; i<len(RootCA);i++ {
		_, err := VerifyRootCACertificate( RootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "Invalid Root CA Certificate")
		}
		opts.Roots.AddCert(RootCA[i])
	}

	if strings.Compare( string(trustedRootCA.Signature), string(RootCA[0].Signature)) != 0 {
                return false, errors.New("VerifyTcbInfo: Trusted CA Verification Failed")
        }

	_, err := pckCert.Verify(opts)
	if err != nil {
		log.Error("Error in PCKCert Verification:", err.Error())
		return false, errors.Wrap(err,"VerifyPCKCertificate: verify certificate")
	}

	for i:=0; i<len(crl); i++{
		log.Debug("CRL Revoked Certifate Count:", len(crl[i].TBSCertList.RevokedCertificates))
		for _, crlObj := range crl[i].TBSCertList.RevokedCertificates  {
			if pckCert.SerialNumber.Cmp(crlObj.SerialNumber) ==  0  {
				log.Error("PCK Certificate is Revoked")
				return false, errors.New("VerifyPCKCertificate: PCK Certificate is Revoked")
			}
		}
	}
	return true, nil
}
