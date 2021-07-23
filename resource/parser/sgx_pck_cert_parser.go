/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v5"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/constants"
	"intel/isecl/sqvs/v5/resource/utils"
	"intel/isecl/sqvs/v5/resource/verifier"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

type PckCRL struct {
	PckCRLURLs     []string
	PckCRLObjs     []*pkix.CertificateList
	RootCA         map[string]*x509.Certificate
	IntermediateCA map[string]*x509.Certificate
}

type PckCert struct {
	PckCertObj           *x509.Certificate
	FmspcStr             string
	TcbCompLevels        []byte
	PckCRL               PckCRL
	RequiredExtension    map[string]asn1.ObjectIdentifier
	RequiredSGXExtension map[string]asn1.ObjectIdentifier
}

func NewPCKCertObj(certBlob []byte) *PckCert {
	if len(certBlob) < 1 {
		log.Error("PckCertParsed Object Spawn: Pck Cert Blob is Empty")
		return nil
	}

	parsedPck := new(PckCert)
	err := parsedPck.genCertObj(certBlob)
	if err != nil {
		log.Error("NewPCKCertObj: Generate Certificate Object Error", err.Error())
		return nil
	}
	parsedPck.genPckCertRequiredExtMap()
	_, err = verifier.CheckMandatoryExt(parsedPck.PckCertObj, parsedPck.getPckCertRequiredExtMap())
	if err != nil {
		log.Error("NewPCKCertObj: VerifyRequiredExtensions not found", err.Error())
		return nil
	}
	parsedPck.genPckCertRequiredSgxExtMap()
	_, err = verifier.CheckMandatorySGXExt(parsedPck.PckCertObj, parsedPck.getPckCertRequiredSgxExtMap())
	if err != nil {
		log.Error("NewPCKCertObj: VerifyRequiredSGXExtensions not found", err.Error())
		return nil
	}

	err = parsedPck.parseFMSPCValue()
	if err != nil {
		log.Error("NewPCKCertObj: Fmspc Parse error", err.Error())
		return nil
	}

	err = parsedPck.parseTcbExtensions()
	if err != nil {
		log.Error("NewPCKCertObj: Tcb Extensions Parse error", err.Error())
		return nil
	}

	err = parsedPck.parsePckCrl()
	if err != nil {
		log.Error("NewPCKCertObj: PCK CRL Parse error", err.Error())
		return nil
	}
	return parsedPck
}

func (e *PckCert) genPckCertRequiredExtMap() {
	e.RequiredExtension = make(map[string]asn1.ObjectIdentifier)
	e.RequiredExtension[verifier.ExtAuthorityKeyIdentifierOid.String()] = verifier.ExtAuthorityKeyIdentifierOid
	e.RequiredExtension[verifier.ExtCRLDistributionPointOid.String()] = verifier.ExtCRLDistributionPointOid
	e.RequiredExtension[verifier.ExtKeyUsageOid.String()] = verifier.ExtKeyUsageOid
	e.RequiredExtension[verifier.ExtBasicConstrainsOid.String()] = verifier.ExtBasicConstrainsOid
}

func (e *PckCert) genPckCertRequiredSgxExtMap() {
	e.RequiredSGXExtension = make(map[string]asn1.ObjectIdentifier)
	e.RequiredSGXExtension[verifier.ExtSgxPPIDOid.String()] = verifier.ExtSgxPPIDOid
	e.RequiredSGXExtension[verifier.ExtSgxTCBOid.String()] = verifier.ExtSgxTCBOid
	e.RequiredSGXExtension[verifier.ExtSgxPCEIDOid.String()] = verifier.ExtSgxPCEIDOid
	e.RequiredSGXExtension[verifier.ExtSgxFMSPCOid.String()] = verifier.ExtSgxFMSPCOid
	e.RequiredSGXExtension[verifier.ExtSgxSGXTypeOid.String()] = verifier.ExtSgxSGXTypeOid
}

func (e *PckCert) getPckCertRequiredExtMap() map[string]asn1.ObjectIdentifier {
	return e.RequiredExtension
}

func (e *PckCert) getPckCertRequiredSgxExtMap() map[string]asn1.ObjectIdentifier {
	return e.RequiredSGXExtension
}

func (e *PckCert) genCertObj(certBlob []byte) error {
	var err error
	block, _ := pem.Decode(certBlob)
	e.PckCertObj, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "genCertObj: Failed to parse Certificate")
	}
	return nil
}

func (e *PckCert) GetFmspcValue() string {
	return e.FmspcStr
}

func (e *PckCert) GetPckCertTcbLevels() []byte {
	return e.TcbCompLevels
}

func (e *PckCert) parseFMSPCValue() error {
	var ext pkix.Extension
	var err error
	for i := 0; i < len(e.PckCertObj.Extensions); i++ {
		ext = e.PckCertObj.Extensions[i]
		if verifier.ExtSgxOid.Equal(ext.Id) {

			var asn1Extensions []asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
			if err != nil {
				return errors.Wrap(err, "Asn1 Extension Unmarshal failed")
			}

			var sgxExtension pkix.Extension
			for j := 0; j < len(asn1Extensions); j++ {

				_, err = asn1.Unmarshal(asn1Extensions[j].FullBytes, &sgxExtension)
				if err != nil {
					log.Info("Asn1 Extension Unmarshal failed for index:", j)
				}
				if verifier.ExtSgxFMSPCOid.Equal(sgxExtension.Id) {
					e.FmspcStr = hex.EncodeToString(sgxExtension.Value)
					log.WithField("FMSPC hex value", e.FmspcStr).Debug("Fmspc Value from cert")
					return nil
				}
			}
		}
	}
	log.Error("Fmspc Value not found in Extension")
	return errors.Wrap(err, "Fmspc Value not found in Extension")
}

type TcbExtn struct {
	ID    asn1.ObjectIdentifier
	Value int
}

func (e *PckCert) parseTcbExtensions() error {
	var ext pkix.Extension
	e.TcbCompLevels = make([]byte, constants.MaxTCBCompLevels)

	for i := 0; i < len(e.PckCertObj.Extensions); i++ {
		ext = e.PckCertObj.Extensions[i]
		if verifier.ExtSgxOid.Equal(ext.Id) {
			var asn1Extensions []asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
			if err != nil {
				return errors.Wrap(err, "Asn1 Extension Unmarshal failed")
			}

			var oid asn1.ObjectIdentifier
			for j, sgxExt := range asn1Extensions {
				var rest []byte
				rest, err = asn1.Unmarshal(sgxExt.Bytes, &oid)
				if err != nil {
					log.Info("Asn1 Extension Unmarshal failed for index:", j)
				}
				if verifier.ExtSgxTCBOid.Equal(oid) {
					var tcbExts []asn1.RawValue
					_, err = asn1.Unmarshal(rest, &tcbExts)
					if err != nil {
						log.Info("Asn1 Extension Unmarshal failed for index:", j)
					}
					for k, tcbExt := range tcbExts {
						var ext2 TcbExtn
						rest, _ = asn1.Unmarshal(tcbExt.FullBytes, &ext2)
						if verifier.ExtSgxTcbPceSvnOid.Equal(ext2.ID) {
							var h, l = uint8(ext2.Value >> 8), uint8(ext2.Value & 0xff)
							e.TcbCompLevels[k] = l
							e.TcbCompLevels[k+1] = h
						} else {
							e.TcbCompLevels[k] = byte(ext2.Value)
						}
					}
				}
			}
		}
	}
	return nil
}

func (e *PckCert) GetECDSAPublicKey() *ecdsa.PublicKey {
	return e.PckCertObj.PublicKey.(*ecdsa.PublicKey)
}

func (e *PckCert) GetPckCrlURL() []string {
	return e.PckCRL.PckCRLURLs
}

func (e *PckCert) GetPckCrlObj() []*pkix.CertificateList {
	return e.PckCRL.PckCRLObjs
}

func (e *PckCert) GetPckCrlInterCaList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.PckCRL.IntermediateCA))
	var i int
	for _, v := range e.PckCRL.IntermediateCA {
		interMediateCAArr[i] = v
		i++
	}
	log.Debug("GetPckCrlInterCaList:", len(interMediateCAArr))
	return interMediateCAArr
}

func (e *PckCert) GetPckCrlRootCaList() []*x509.Certificate {
	rootCAArr := make([]*x509.Certificate, len(e.PckCRL.RootCA))
	var i int
	for _, v := range e.PckCRL.RootCA {
		rootCAArr[i] = v
		i++
	}
	log.Debug("GetPckCrlRootCaList:", len(rootCAArr))
	return rootCAArr
}

func (e *PckCert) parsePckCrl() error {
	e.PckCRL.PckCRLURLs = e.PckCertObj.CRLDistributionPoints
	e.PckCRL.PckCRLObjs = make([]*pkix.CertificateList, len(e.PckCRL.PckCRLURLs))

	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("parsePckCrl: Configuration pointer is null"), "Config error")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return errors.Wrap(err, "parsePckCrl: Error in getting client object")
	}

	for i := 0; i < len(e.PckCRL.PckCRLURLs); i++ {
		url := e.PckCRL.PckCRLURLs[i]

		scsURL := conf.SCSBaseURL
		if !strings.Contains(url, scsURL) {
			a := regexp.MustCompile(`v\d`)
			splitURL := a.Split(url, -1)
			if len(splitURL) != 2 {
				return errors.Wrap(err, "parsePckCrl: Invalid PCK CRL URL")
			}
			finalURL := strings.Trim(splitURL[1], "&encoding")
			url = scsURL + finalURL
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return errors.Wrap(err, "parsePckCrl: Failed to Get New request")
		}

		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if resp != nil {
			defer func() {
				derr := resp.Body.Close()
				if derr != nil {
					log.WithError(derr).Error("Error closing pckcrl response")
				}
			}()
		}

		if err != nil {
			return errors.Wrap(err, "failed to get pckcrl response from scs")
		}

		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("parsePckCrl: Invalid status code received:%d", resp.StatusCode))
		}

		crlBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "parsePckCrl: failed to read pckcrl response body")
		}

		crlDer, err := base64.StdEncoding.DecodeString(string(crlBody))
		if err != nil {
			return errors.Wrap(err, "parsePckCrl: failed to base64 decode crl blob")
		}

		crlObj, err := x509.ParseDERCRL(crlDer)
		if err != nil {
			return errors.Wrap(err, "parsePckCrl: failed to Parse der encoded crl")
		}

		e.PckCRL.PckCRLObjs[i] = crlObj
		certChainList, err := utils.GetCertObjList(resp.Header.Get("SGX-PCK-CRL-Issuer-Chain"))
		if err != nil {
			return errors.Wrap(err, "parsePckCrl: failed to get cert list")
		}

		e.PckCRL.RootCA = make(map[string]*x509.Certificate)
		e.PckCRL.IntermediateCA = make(map[string]*x509.Certificate)

		var intermediateCACount int
		var rootCACount int
		for i := 0; i < len(certChainList); i++ {
			cert := certChainList[i]
			if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
				rootCACount++
				e.PckCRL.RootCA[cert.Subject.String()] = cert
			}
			if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Processor CA") ||
				strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Platform CA") {
				intermediateCACount++
				e.PckCRL.IntermediateCA[cert.Subject.String()] = cert
			}
			log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
		}

		if intermediateCACount == 0 || rootCACount == 0 {
			return errors.Wrap(err, "parsePckCrl: PCK CRL- Root CA/Intermediate CA Invalid count")
		}
	}
	return err
}
