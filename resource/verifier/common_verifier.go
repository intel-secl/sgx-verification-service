/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"strings"
	"crypto/x509"
	"encoding/asn1"
	"crypto/sha256"
	"crypto/x509/pkix"

	clog "intel/isecl/lib/common/log"
	//"intel/isecl/svs/resource/utils"
	"github.com/pkg/errors"
)


var ExtCRLDistributionPointOid          asn1.ObjectIdentifier   = asn1.ObjectIdentifier{2,5,29,31}
var ExtSubjectKeyIdentifierOid          asn1.ObjectIdentifier   = asn1.ObjectIdentifier{2,5,29,14}
var ExtKeyUsageOid                      asn1.ObjectIdentifier   = asn1.ObjectIdentifier{2,5,29,15}
var ExtBasicConstrainsOid               asn1.ObjectIdentifier   = asn1.ObjectIdentifier{2,5,29,19}
var ExtAuthorityKeyIdentifierOid        asn1.ObjectIdentifier   = asn1.ObjectIdentifier{2,5,29,35}
var ExtSgxOid                           asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1}
var ExtSgxPPIDOid                       asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1,1}
var ExtSgxTCBOid                        asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1,2}
var ExtSgxPCEIDOid                      asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1,3}
var ExtSgxFMSPCOid                      asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1,4}
var ExtSgxSGXTypeOid                    asn1.ObjectIdentifier   = asn1.ObjectIdentifier{1,2,840,113741,1,13,1,5}

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func VerifyRequiredExtensions( cert *x509.Certificate, requiredExtDict map[string]asn1.ObjectIdentifier ) ( bool, error ){
	log.Trace("resource/verifier/common_verifier:VerifyRequiredExtensions() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifyRequiredExtensions() Leaving")

	if cert == nil || len(requiredExtDict) == 0 {
		return false, errors.New("VerifyRequiredExtensions: Certificate Object is nul or requiredExtDict is Empty")
	}

        var ext pkix.Extension
        var present int = 0
        for i:=0; i< len(cert.Extensions); i++ {
                ext = cert.Extensions[i]
                //log.Debug("VerifyRequiredExtensions: Extension[",i,"]:", ext.Id.String())
                if _, ok := requiredExtDict[ext.Id.String()]; ok {
                         //log.Debug("Extension[",i,"]:", ext.Id.String()," found in list")
                         present += 1
                }
        }
        if present != len(requiredExtDict) {
                return false, errors.New("VerifyRequiredExtensions: Required Extension not found")
        }
        return true, nil
}

func GetRootCARequiredExtMap() (map[string]asn1.ObjectIdentifier){
	log.Trace("resource/verifier/common_verifier:GetRootCARequiredExtMap() Entering")
	defer log.Trace("resource/verifier/common_verifier:GetRootCARequiredExtMap() Leaving")

        RequiredExtension := make(map[string]asn1.ObjectIdentifier)
        RequiredExtension[ExtAuthorityKeyIdentifierOid.String()]     = ExtAuthorityKeyIdentifierOid
        RequiredExtension[ExtCRLDistributionPointOid.String()]       = ExtCRLDistributionPointOid
        RequiredExtension[ExtSubjectKeyIdentifierOid.String()]       = ExtSubjectKeyIdentifierOid  
        RequiredExtension[ExtKeyUsageOid.String()]                   = ExtKeyUsageOid
        RequiredExtension[ExtBasicConstrainsOid.String()]            = ExtBasicConstrainsOid
	return RequiredExtension
}

func VerifyString( input string, cmpStr string )( bool ){
	log.Trace("resource/verifier/common_verifier:VerifyString() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifyString() Leaving")
	
	if len(input)==0 || len(cmpStr)==0 {
		return false
	}
	cmpStrArr := strings.Split( cmpStr, "|")

	for i:=0; i<len(cmpStrArr);i++ {
		if strings.Compare(cmpStrArr[i],  input) == 0 {
			return true
		}
	}

	log.Errorf("VerifyString: Input:%s not mached with %s\n", input, cmpStr)
	return false
}

func VerifyInterCACertificate( interCA *x509.Certificate, rootCA []*x509.Certificate, subjectStr string ) (bool, error){
	log.Trace("resource/verifier/common_verifier:VerifyInterCACertificate() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifyInterCACertificate() Leaving")

	if rootCA == nil || len(subjectStr) == 0 {
		return false, errors.New("VerifyInterCACertificate: Certificate Object is nul or requiredExtDict is Empty")
	}

	if !VerifyString(interCA.Subject.String(), subjectStr) {
		return false, errors.New("VerifyInterCACertificate: Invalid Certificate Subject: "+ interCA.Subject.String()+
						 "not matched with "+  subjectStr )
	}
	_, err := VerifyRequiredExtensions( interCA, GetRootCARequiredExtMap())
	if err != nil {
		return false, errors.Wrap(err, "VerifyInterCACertificate: ")
	}

	var opts x509.VerifyOptions
	opts.Roots = x509.NewCertPool()
 	for i:=0; i< len(rootCA); i++ {
		opts.Roots.AddCert(rootCA[i])
	}
	_, err = interCA.Verify(opts)
        if err != nil {
                return false, errors.Wrap(err, "VerifyInterCACertificate: Verification failure")
        }
	return true, nil
}

func VerifyRootCACertificate( rootCA *x509.Certificate, subjectStr string ) (bool, error){
	log.Trace("resource/verifier/common_verifier:VerifyRootCACertificate() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifyRootCACertificate() Leaving")


	if rootCA == nil || len(subjectStr) == 0 {
		return false, errors.New("VerifyRootCACertificate: Certificate Object is nul or requiredExtDict is Empty")
	}

	var opts x509.VerifyOptions

	if strings.Compare(subjectStr,  rootCA.Subject.String()) != 0 {
		return false, errors.New("VerifyRootCACertificate: Invalid Certificate Subject: "+ rootCA.Subject.String() )
	}
		
	if strings.Compare(rootCA.Issuer.String(),  rootCA.Subject.String()) != 0 {
		return false, errors.New("VerifyRootCACertificate: Invalid Certificate Subject/Verifier differed: "+ rootCA.Subject.String() )
	}

	_, err := VerifyRequiredExtensions( rootCA, GetRootCARequiredExtMap())
	if err != nil {
		return false, errors.Wrap(err, "VerifyRootCACertificate: ")
	}

	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(rootCA)

	_, err = rootCA.Verify(opts)
        if err != nil {
                return false, errors.Wrap(err, "VerifyRootCACertificate: Verification failure:")
        }

	err =  rootCA.CheckSignature( rootCA.SignatureAlgorithm, rootCA.RawTBSCertificate, rootCA.Signature)
	if err != nil {
		return false, errors.Wrap(err, "VerifyRootCACertificate: Signature check failed ")
	}
	return true, nil
}

func VerifyRequiredSGXExtensions( cert *x509.Certificate, requiredExtDict map[string]asn1.ObjectIdentifier  ) ( bool, error){
	log.Trace("resource/verifier/common_verifier:VerifyRequiredSGXExtensions() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifyRequiredSGXExtensions() Leaving")

	if cert == nil || len(requiredExtDict) == 0 {
		return false, errors.New("VerifyRequiredSGXExtensions: Certificate Object is nul or requiredExtDict is Empty")
	}

        var present int = 0
        var ext, sgxExt pkix.Extension
        var sgxExtensions []asn1.RawValue

        for i:=0; i< len(cert.Extensions); i++ {
                ext = cert.Extensions[i]
                if ExtSgxOid.Equal(ext.Id) == true {
                        _, err := asn1.Unmarshal(ext.Value, &sgxExtensions)
                        if err != nil {
                                return false, errors.Wrap(err, "VerifyRequiredSGXExtensions: unmarshal failed")
                        }

                        log.Debug("Required Extension Dictionary", requiredExtDict)
                        for j:=0; j<len(sgxExtensions); j++ {

                                _, err = asn1.Unmarshal(sgxExtensions[j].FullBytes, &sgxExt)
                                log.Debug("SGXExtension[",j,"]:", sgxExt.Id.String())
                                if _, ok := requiredExtDict[sgxExt.Id.String()]; ok {
                                        log.Debug("SGXExtension[",j,"]:", sgxExt.Id.String()," found in list")
                                        present += 1
                                }
                        }
                }
        }
        if present != len(requiredExtDict) {
                return false, errors.New("VerifyRequiredSGXExtensions: Required SGX Extension not found")
        }
        return true, nil
}

func VerifiySHA256Hash( hash []byte, blob []byte) ( bool, error ){
	log.Trace("resource/verifier/common_verifier:VerifiySHA256Hash() Entering")
	defer log.Trace("resource/verifier/common_verifier:VerifiySHA256Hash() Leaving")

	if len(hash) == 0 || len(blob) == 0 || len(hash) != sha256.Size {
                return false, errors.New("VerifiySHA256Hash: Invalid hash verify input data")
	}

	h := sha256.New()
	h.Write(blob)
	hashValue := h.Sum(nil)

	if len(hashValue) != sha256.Size {
		return false, errors.New("VerifiySHA256Hash: Error in Hash generation")
	}

	//utils.DumpDataInHex("Quote Hash", hash, len(hash))
	//utils.DumpDataInHex("Gen Hash", hashValue, len(hashValue))
	for i:=0;i<len(hash);i++{
		if hashValue[i] != hash[i]{
			return false, errors.New("VerifiySHA256Hash: Public 256 validation failed")
		}
	}
	log.Info("Verifiy SHA256 Hash Passed...")
	return true, nil
}
