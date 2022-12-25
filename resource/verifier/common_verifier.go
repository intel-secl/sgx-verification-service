/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	clog "intel/isecl/lib/common/v5/log"
	"strings"

	"github.com/pkg/errors"
)

var ExtCRLDistributionPointOid = asn1.ObjectIdentifier{2, 5, 29, 31}
var ExtSubjectKeyIdentifierOid = asn1.ObjectIdentifier{2, 5, 29, 14}
var ExtKeyUsageOid = asn1.ObjectIdentifier{2, 5, 29, 15}
var ExtBasicConstrainsOid = asn1.ObjectIdentifier{2, 5, 29, 19}
var ExtAuthorityKeyIdentifierOid = asn1.ObjectIdentifier{2, 5, 29, 35}
var ExtSgxOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
var ExtSgxPPIDOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 1}
var ExtSgxTCBOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2}
var ExtSgxPCEIDOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 3}
var ExtSgxFMSPCOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
var ExtSgxSGXTypeOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 5}
var ExtSgxTcbPceSvnOid = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2, 17}

var log = clog.GetDefaultLogger()

func CheckMandatoryExt(cert *x509.Certificate, requiredExtDict map[string]asn1.ObjectIdentifier) error {
	var ext pkix.Extension
	var extCount int
	for i := 0; i < len(cert.Extensions); i++ {
		ext = cert.Extensions[i]
		if _, ok := requiredExtDict[ext.Id.String()]; ok {
			extCount++
		}
	}
	if extCount != len(requiredExtDict) {
		return errors.New("CheckMandatoryExt: Required Extension not found")
	}
	return nil
}

func CheckMandatorySGXExt(cert *x509.Certificate, requiredExtDict map[string]asn1.ObjectIdentifier) error {
	var extCount int
	var ext, sgxExt pkix.Extension
	var sgxExtensions []asn1.RawValue

	for i := 0; i < len(cert.Extensions); i++ {
		ext = cert.Extensions[i]
		if ExtSgxOid.Equal(ext.Id) {
			_, err := asn1.Unmarshal(ext.Value, &sgxExtensions)
			if err != nil {
				return errors.Wrap(err, "CheckMandatorySGXExt: unmarshal failed")
			}

			log.Debug("Required Extension Dictionary: ", requiredExtDict)
			for j := 0; j < len(sgxExtensions); j++ {
				_, err = asn1.Unmarshal(sgxExtensions[j].FullBytes, &sgxExt)
				if err != nil {
					log.Debug("failed to unmarshal sgx extensions")
				}
				log.Debug("SGXExtension[", j, "]:", sgxExt.Id.String())
				if _, ok := requiredExtDict[sgxExt.Id.String()]; ok {
					log.Debug("SGXExtension[", j, "]:", sgxExt.Id.String(), " found in list")
					extCount++
				}
			}
		}
	}
	if extCount != len(requiredExtDict) {
		return errors.New("CheckMandatorySGXExt: Required SGX Extension not found")
	}
	return nil
}

func getMandatoryCertExtMap() map[string]asn1.ObjectIdentifier {
	RequiredExtension := make(map[string]asn1.ObjectIdentifier)
	RequiredExtension[ExtAuthorityKeyIdentifierOid.String()] = ExtAuthorityKeyIdentifierOid
	RequiredExtension[ExtCRLDistributionPointOid.String()] = ExtCRLDistributionPointOid
	RequiredExtension[ExtSubjectKeyIdentifierOid.String()] = ExtSubjectKeyIdentifierOid
	RequiredExtension[ExtKeyUsageOid.String()] = ExtKeyUsageOid
	RequiredExtension[ExtBasicConstrainsOid.String()] = ExtBasicConstrainsOid
	return RequiredExtension
}

func verifyCaSubject(input, cmpStr string) bool {
	if input == "" || cmpStr == "" {
		return false
	}
	cmpStrArr := strings.Split(cmpStr, "|")

	for i := 0; i < len(cmpStrArr); i++ {
		if strings.Compare(cmpStrArr[i], input) == 0 {
			return true
		}
	}

	log.Errorf("verifyCaSubject: Input:%s did not match with %s\n", input, cmpStr)
	return false
}

func verifyInterCaCert(interCA *x509.Certificate, rootCA []*x509.Certificate, subjectStr string) error {
	if !verifyCaSubject(interCA.Subject.String(), subjectStr) {
		return errors.New("verifyInterCaCert: Invalid Certificate Subject: " + interCA.Subject.String() +
			"did not match with " + subjectStr)
	}
	err := CheckMandatoryExt(interCA, getMandatoryCertExtMap())
	if err != nil {
		return errors.Wrap(err, "verifyInterCaCert: ")
	}

	var opts x509.VerifyOptions
	opts.Roots = x509.NewCertPool()
	for i := 0; i < len(rootCA); i++ {
		opts.Roots.AddCert(rootCA[i])
	}
	_, err = interCA.Verify(opts)
	if err != nil {
		return errors.Wrap(err, "verifyInterCaCert: Verification failure")
	}
	return nil
}

func verifyRootCaCert(rootCA *x509.Certificate, subjectStr string) error {
	var opts x509.VerifyOptions

	if strings.Compare(subjectStr, rootCA.Subject.String()) != 0 {
		return errors.New("verifyRootCaCert: Invalid Certificate Subject: " + rootCA.Subject.String())
	}

	if strings.Compare(rootCA.Issuer.String(), rootCA.Subject.String()) != 0 {
		return errors.New("verifyRootCaCert: the certificate does not appear to be a Root CA")
	}

	err := CheckMandatoryExt(rootCA, getMandatoryCertExtMap())
	if err != nil {
		return errors.Wrap(err, "verifyRootCaCert: ")
	}

	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(rootCA)

	_, err = rootCA.Verify(opts)
	if err != nil {
		return errors.Wrap(err, "verifyRootCaCert: Root CA Verification failure:")
	}

	err = rootCA.CheckSignature(rootCA.SignatureAlgorithm, rootCA.RawTBSCertificate, rootCA.Signature)
	if err != nil {
		return errors.Wrap(err, "verifyRootCaCert: Root CA Signature check failed ")
	}
	return nil
}

func VerifySHA256Hash(hash, blob []byte) error {
	if len(hash) != sha256.Size {
		return errors.New("VerifySHA256Hash: Invalid hash verify input data")
	}

	h := sha256.New()
	h.Write(blob)
	hashValue := h.Sum(nil)

	if len(hashValue) != sha256.Size {
		return errors.New("VerifySHA256Hash: Error in Hash generation")
	}

	ret := bytes.Equal(hashValue, hash)
	if !ret {
		return errors.New("VerifySHA256Hash: hash verification failed")
	}
	return nil
}
