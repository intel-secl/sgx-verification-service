/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"crypto/x509/pkix"
	"time"
	"errors"
	"crypto/x509"
	"strings"
	"intel/isecl/svs/constants"

	log "github.com/sirupsen/logrus"
)


func CheckExpiry(crl *pkix.CertificateList)(bool){
	if crl.HasExpired(time.Now()){
		log.Error("CRL Expired")
		return false
	}
	return true
}

func VerifyPCKCRLIssuer( crl *pkix.CertificateList) (bool){
	issuer := crl.TBSCertList.Issuer.String()
	return VerifyString( issuer, constants.SGXCRLIssuerStr)
}

func VerifyPCKCRL(crlUrl []string, crlList []*pkix.CertificateList, interCA []*x509.Certificate, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate)(bool, error){
	if len(crlList) == 0 || len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyPCKCRL: CRL List/InterCA/RootCA is empty")
	}

        for i:=0; i<len(interCA);i++ {
                _, err := VerifyInterCACertificate( interCA[i], rootCA, constants.SGXInterCACertSubjectStr)
                if err != nil {
                        return false, errors.New("VerifyPCKCRL: VerifyInterCACertificate failed: "+ err.Error())
                }
        }
        for i:=0; i<len(rootCA);i++ {
                _, err := VerifyRootCACertificate( rootCA[i], constants.SGXRootCACertSubjectStr)
                if err != nil {
                        return false, errors.New("VerifyPCKCRL: VerifyRootCACertificate failed: "+ err.Error())
                }
        }

	log.Printf("CRL List:%d", len(crlUrl))
	var signPassCount int=0
	for i:=0; i<len(crlList); i++{
		ret := CheckExpiry(crlList[i])
		if ret != true {
			return false, errors.New("VerifyPCKCRL: CRL is Expired"+crlUrl[i])
		}
		ret = VerifyPCKCRLIssuer(crlList[i])
		if ret != true {
			return false, errors.New("VerifyPCKCRL: CRL Issuer is Invalid: "+crlUrl[i])
		}


		for j:=0;j<len(interCA);j++{
			err :=  interCA[i].CheckCRLSignature( crlList[i] )
			if err == nil {
				signPassCount += 1
			}
		}
	
		if signPassCount == 0 {
			return false, errors.New("VerifyPCKCRL: Signature Verification failed")
		}
	}

	if strings.Compare( string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyPCKCRL: Trusted CA Verification Failed")
	}
	return true, nil
}
