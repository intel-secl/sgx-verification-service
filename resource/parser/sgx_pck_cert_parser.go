/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package parser

import (
	"fmt"
	"regexp"
	"strings"
	"net/http"
	"io/ioutil"
       	"crypto/x509"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"encoding/asn1"
	"crypto/x509/pkix"

	"github.com/pkg/errors"
	"intel/isecl/svs/resource/utils"
	"intel/isecl/svs/resource/verifier"
)

type PckCRL struct {
	PckCRLUrls 		[]string
	PckCRLObjs 		[]*pkix.CertificateList
	RootCA     		map[string]*x509.Certificate
	IntermediateCA     	map[string]*x509.Certificate
}

type PckCert struct {
	PckCertObj 		*x509.Certificate
	FmspcStr 		string
	PckCRL 			PckCRL
	RequiredExtension 	map[string]asn1.ObjectIdentifier
	RequiredSGXExtension 	map[string]asn1.ObjectIdentifier
}

func NewPCKCertObj(certBlob []byte)( *PckCert ){
	log.Trace("resource/parser/sgx_pck_cert_parser:NewPCKCertObj() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:NewPCKCertObj() Leaving")

	if len(certBlob) < 1 {
		log.Debug("PckCertParsed Object Spawn: Pck Cert Blob is Empty")
		return nil
	}

	parsedPck := new( PckCert )
	err := parsedPck.GenCertObj( certBlob )
	if err != nil {
		log.Debug("NewPCKCertObj: Generate Certificate Object Error", err.Error())
		return nil
	}
	parsedPck.GeneratePckCertRequiredExtMap()
	_, err = verifier.VerifyRequiredExtensions( parsedPck.PckCertObj, parsedPck.GetPckCertRequiredExtMap())
	if err != nil {
		log.Debug("NewPCKCertObj: VerifyRequiredExtensions not found", err.Error())
		return nil
	}
	parsedPck.GeneratePckCertRequiredSgxExtMap()
	_, err = verifier.VerifyRequiredSGXExtensions( parsedPck.PckCertObj, parsedPck.GetPckCertRequiredSgxExtMap())
	if err != nil {
		log.Debug("NewPCKCertObj: VerifyRequiredSGXExtensions not found", err.Error())
		return nil
	}

	err = parsedPck.ParseFMSPCValue()
	if err != nil {
		log.Debug("NewPCKCertObj: Fmspc Parse error", err.Error())
		return nil
	}
	err = parsedPck.ParsePCKCRL()
	if err != nil {
		log.Debug("NewPCKCertObj: PCK CRL Parse error", err.Error())
		return nil
	}
	return parsedPck
}


func (e *PckCert) GeneratePckCertRequiredExtMap() {
	log.Trace("resource/parser/sgx_pck_cert_parser:GeneratePckCertRequiredExtMap() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GeneratePckCertRequiredExtMap() Leaving")

	e.RequiredExtension = make(map[string]asn1.ObjectIdentifier)
	e.RequiredExtension[verifier.ExtAuthorityKeyIdentifierOid.String()]	= verifier.ExtAuthorityKeyIdentifierOid
	e.RequiredExtension[verifier.ExtCRLDistributionPointOid.String()] 	= verifier.ExtCRLDistributionPointOid
	e.RequiredExtension[verifier.ExtKeyUsageOid.String()]			= verifier.ExtKeyUsageOid
	e.RequiredExtension[verifier.ExtBasicConstrainsOid.String()]		= verifier.ExtBasicConstrainsOid
}


func (e *PckCert) GeneratePckCertRequiredSgxExtMap() {
	log.Trace("resource/parser/sgx_pck_cert_parser:GeneratePckCertRequiredSgxExtMap() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GeneratePckCertRequiredSgxExtMap() Leaving")

	e.RequiredSGXExtension = make(map[string]asn1.ObjectIdentifier)
	e.RequiredSGXExtension[verifier.ExtSgxPPIDOid.String()]			= verifier.ExtSgxPPIDOid
	e.RequiredSGXExtension[verifier.ExtSgxTCBOid.String()] 			= verifier.ExtSgxTCBOid
	e.RequiredSGXExtension[verifier.ExtSgxPCEIDOid.String()]		= verifier.ExtSgxPCEIDOid
	e.RequiredSGXExtension[verifier.ExtSgxFMSPCOid.String()]		= verifier.ExtSgxFMSPCOid
	e.RequiredSGXExtension[verifier.ExtSgxSGXTypeOid.String()]		= verifier.ExtSgxSGXTypeOid
}

func (e *PckCert) GetPckCertRequiredExtMap() ( map[string]asn1.ObjectIdentifier ){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCertRequiredExtMap() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCertRequiredExtMap() Leaving")

	return e.RequiredExtension
}
func (e *PckCert) GetPckCertRequiredSgxExtMap() ( map[string]asn1.ObjectIdentifier ){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCertRequiredSgxExtMap() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCertRequiredSgxExtMap() Leaving")

	return e.RequiredSGXExtension
}

func (e *PckCert) GenCertObj( certBlob []byte )( error ){
	log.Trace("resource/parser/sgx_pck_cert_parser:NewPCKCertObj() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:NewPCKCertObj() Leaving")

	var err error
	block, _ := pem.Decode([]byte(certBlob))
        e.PckCertObj, err = x509.ParseCertificate( block.Bytes )
	if err != nil {
		return errors.Wrap(err,"GenCertObj: Failed to parse Certificate")
	}
	return nil
}

func (e *PckCert) GetFMSPCValue() string{
	log.Trace("resource/parser/sgx_pck_cert_parser:GetFMSPCValue() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetFMSPCValue() Leaving")

	fmspcValue := e.FmspcStr
	return fmspcValue
}

func (e *PckCert) ParseFMSPCValue()(error){
	log.Trace("resource/parser/sgx_pck_cert_parser:ParseFMSPCValue() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:ParseFMSPCValue() Leaving")

        var ext pkix.Extension
	var err error
        for i:=0; i< len(e.PckCertObj.Extensions); i++ {
                ext=e.PckCertObj.Extensions[i]
                if verifier.ExtSgxOid.Equal(ext.Id) == true {

                        var asn1Extensions []asn1.RawValue
                        _, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
                        if err != nil {
                                return errors.Wrap(err,"Asn1 Extension Unmarshal failed")
                        }

                        var sgxExtension pkix.Extension
                        for j:=0; j<len(asn1Extensions); j++ {

                                _, err = asn1.Unmarshal(asn1Extensions[j].FullBytes, &sgxExtension)
                                if err != nil {
                                        log.Trace("Warning: Asn1 Extension Unmarshal failed - 2 for index:", j)
                                }
                                if verifier.ExtSgxFMSPCOid.Equal(sgxExtension.Id) == true {
                                        e.FmspcStr=hex.EncodeToString(sgxExtension.Value)
                                        log.WithField("FMSPC hex value", e.FmspcStr).Debug("Fmspc Value from cert")
                                        log.WithField("FMSPC hex value", e.FmspcStr).Debug("Fmspc Value from cert")
                                        return nil
                                }
                        }
                }
        }
	log.Info("Fmspc Value not found in Extension")
        return errors.Wrap(err,"Fmspc Value not found in Extension")
}

func (e *PckCert) GetECDSAPublicKey() ( *ecdsa.PublicKey ){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetECDSAPublicKey() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetECDSAPublicKey() Leaving")

	return e.PckCertObj.PublicKey.(*ecdsa.PublicKey)
} 

func (e *PckCert) GetPckCRLURLs() ( []string ){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLURLs() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLURLs() Leaving")

	return e.PckCRL.PckCRLUrls
} 

func (e *PckCert) GetPckCRLObj() ( []*pkix.CertificateList ){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLObj() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLObj() Leaving")

	return e.PckCRL.PckCRLObjs
} 

func (e *PckCert) GetPckCRLInterCAList()([]*x509.Certificate){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLInterCAList() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLInterCAList() Leaving")

        interMediateCAArr := make( []*x509.Certificate, len(e.PckCRL.IntermediateCA))
        var i  int=0
        for _, v := range e.PckCRL.IntermediateCA {
                interMediateCAArr[i] = v
                i += 1
        }
	log.Debug("GetPckCRLInterCAList:", len(interMediateCAArr))
        return interMediateCAArr
}

func (e *PckCert) GetPckCRLRootCAList()([]*x509.Certificate){
	log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLRootCAList() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:GetPckCRLRootCAList() Leaving")

        RootCAArr := make( []*x509.Certificate, len(e.PckCRL.RootCA))
        var i  int=0
        for _, v := range e.PckCRL.RootCA {
                RootCAArr[i] = v
                i += 1
        }
	log.Debug("GetPckCRLRootCAList:", len(RootCAArr))
        return RootCAArr
}

func (e *PckCert) ParsePCKCRL() error{
	log.Trace("resource/parser/sgx_pck_cert_parser:ParsePCKCRL() Entering")
	defer log.Trace("resource/parser/sgx_pck_cert_parser:ParsePCKCRL() Leaving")

	e.PckCRL.PckCRLUrls = e.PckCertObj.CRLDistributionPoints
	e.PckCRL.PckCRLObjs = make( []*pkix.CertificateList, len(e.PckCRL.PckCRLUrls))

	for i:=0; i<len(e.PckCRL.PckCRLUrls); i++ {

		client, conf, err := utils.GetHTTPClientObj()
		if err != nil {
			return  errors.Wrap(err, "Failed to get HTTPClientObj")
		}

		url := fmt.Sprintf("%s", e.PckCRL.PckCRLUrls[i])

		scsUrl := conf.SCSBaseUrl
		if !strings.Contains(url, scsUrl){
			a := regexp.MustCompile(`v\d`)
			splitUrl := a.Split(url, -1)
			log.Debug("Splited string:", splitUrl)
			if len(splitUrl) != 2 {
				return errors.Wrap(err, "ParsePCKCRL: Invalid PCK CRL Url")
			}
			url = scsUrl + splitUrl[1]
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
		    return errors.Wrap(err, "ParsePCKCRL: Failed to Get New request")
		}

		resp, err := client.Do( req )
		if err != nil {
		    return errors.Wrap(err, "Client request Failed")
		}

		if resp.StatusCode != 200  {
			return errors.New(fmt.Sprintf("ParsePCKCRL: Invalid status code received:%d", resp.StatusCode))
		}

		crlBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "read Response failed ")
		}
		resp.Body.Close()
		crlObj, err := x509.ParseCRL(crlBody)
		if err != nil {
			return errors.Wrap(err, "failed to ParseCRL")
		}

		e.PckCRL.PckCRLObjs[i] = crlObj
		certChainList, err := utils.GetCertObjListFromStr( string( resp.Header.Get("SGX-PCK-CRL-Issuer-Chain") ))
		if err != nil {
			return errors.Wrap(err, "Failed to ger object list from string")
		}

		e.PckCRL.RootCA = make( map[string]*x509.Certificate )
		e.PckCRL.IntermediateCA = make( map[string]*x509.Certificate )

		var IntermediateCACount int=0
		var RootCACount int=0
		for i:=0;i<len(certChainList);i++ {
			cert := certChainList[i]
			if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
				RootCACount += 1
				e.PckCRL.RootCA[cert.Subject.String()] = cert
			}
			if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Processor CA") ||
                        		strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Platform CA"){
				IntermediateCACount += 1
				e.PckCRL.IntermediateCA[cert.Subject.String()] = cert
			}
                	log.Debug("Cert[" ,i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
		}

		if IntermediateCACount == 0 || RootCACount == 0 {
			return errors.Wrap(err, "PCK CRL- Root CA/Intermediate CA Invalid count")
		}
	}
	return nil
}

