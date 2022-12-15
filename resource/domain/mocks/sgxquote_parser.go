/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"intel/isecl/sqvs/v5/resource/domain"
	"intel/isecl/sqvs/v5/resource/domain/models"
	"intel/isecl/sqvs/v5/resource/verifier"
	"io/ioutil"
)

const (
	trustedSGXRootCA      = "../test/trustedSGXRootCA.pem"
	intermediateSGXRootCA = "../test/intermediateSGXRootCA.pem"
	pckCertFilePath       = "../test/pck-cert.pem"
)

type FakeSGXQuoteParsed struct {
	RawBlob []byte
}

func NewMockSGXQuoteParser(rawBlob []byte) domain.SGXQuoteParser {
	return &FakeSGXQuoteParsed{
		RawBlob: rawBlob,
	}
}

func (fe *FakeSGXQuoteParsed) GetSHA256Hash() []byte {
	return nil
}
func (fe *FakeSGXQuoteParsed) GetQeReportBlob() ([]byte, error) {
	return nil, nil
}
func (fe *FakeSGXQuoteParsed) GetHeaderAndEnclaveReportBlob() ([]byte, error) {
	return nil, nil
}
func (fe *FakeSGXQuoteParsed) GetQeReportAttributes() [models.AttributeSize]byte {
	return [models.AttributeSize]byte{}
}
func (fe *FakeSGXQuoteParsed) GetQeReportMiscSelect() uint32 {
	return 0
}
func (fe *FakeSGXQuoteParsed) GetQeReportMrSigner() [models.HashSize]byte {
	return [models.HashSize]byte{}
}
func (fe *FakeSGXQuoteParsed) GetEnclaveMrSigner() [models.HashSize]byte {
	return [models.HashSize]byte{}
}
func (fe *FakeSGXQuoteParsed) GetQeReportProdID() uint16 {
	return 1
}
func (fe *FakeSGXQuoteParsed) GetEnclaveReportProdID() uint16 {
	return 1
}
func (fe *FakeSGXQuoteParsed) GetQeReportIsvSvn() uint16 {
	return 2
}
func (fe *FakeSGXQuoteParsed) GetEnclaveReportIsvSvn() uint16 {
	return 2
}
func (fe *FakeSGXQuoteParsed) DumpSGXQuote() {

}

func (fe *FakeSGXQuoteParsed) GetQeReportMrEnclave() [32]byte {
	return [32]byte{}
}
func (fe *FakeSGXQuoteParsed) GetEnclaveReportMrEnclave() [32]byte {
	return [32]byte{}
}
func (fe *FakeSGXQuoteParsed) GetEnclaveReportSignature() []byte {
	return nil
}
func (fe *FakeSGXQuoteParsed) GetQeReportSignature() []byte {
	return nil
}
func (fe *FakeSGXQuoteParsed) GetAttestationPublicKey() []byte {
	return nil
}

func readCertFromFile(filePath string) *x509.Certificate {
	certBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Failed to read certificate file")
		return nil
	}

	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		fmt.Println("Failed to decode cert bytes")
		return nil
	}
	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing SGX CA certificate %v", err)
		return nil
	}

	extCRLDistributionPointOid := pkix.Extension{
		Id:       verifier.ExtCRLDistributionPointOid,
		Critical: true,
	}
	x509Cert.Extensions = append(x509Cert.Extensions, extCRLDistributionPointOid)

	extAuthorityKeyIdentifierOid := pkix.Extension{
		Id:       verifier.ExtAuthorityKeyIdentifierOid,
		Critical: true,
	}
	x509Cert.Extensions = append(x509Cert.Extensions, extAuthorityKeyIdentifierOid)

	return x509Cert
}

func (fe *FakeSGXQuoteParsed) GetQuotePckCertObj() *x509.Certificate {
	// create or load certificate with common name - "Intel SGX PCK Certificate"
	return readCertFromFile(pckCertFilePath)

}
func (fe *FakeSGXQuoteParsed) GetQuotePckCertInterCAList() []*x509.Certificate {
	// create or load certificate with common name - "Intel SGX PCK Certificate"
	var intermediateCerts []*x509.Certificate
	thisCert := readCertFromFile(intermediateSGXRootCA)
	if thisCert == nil {
		fmt.Printf("Failed to read certificate")
		return nil
	}
	intermediateCerts = append(intermediateCerts, thisCert)
	return intermediateCerts
}
func (fe *FakeSGXQuoteParsed) GetQuotePckCertRootCAList() []*x509.Certificate {
	// create or load certificate with common name - "Intel SGX PCK Certificate"
	var rootCerts []*x509.Certificate
	thisCert := readCertFromFile(trustedSGXRootCA)
	if thisCert == nil {
		fmt.Printf("Failed to read certificate")
		return nil
	}
	rootCerts = append(rootCerts, thisCert)
	return rootCerts
}
func (fe *FakeSGXQuoteParsed) ParseQuoteCerts() error {
	return nil
}

func (fe *FakeSGXQuoteParsed) ParseRawECDSAQuote(decodedQuote []byte) error {
	return nil
}
