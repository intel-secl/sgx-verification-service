/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/resource/domain/models"
	"net/http"
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
type (
	SGXQuoteParser interface {
		GetSHA256Hash() []byte
		GetQeReportBlob() ([]byte, error)
		GetHeaderAndEnclaveReportBlob() ([]byte, error)
		GetQeReportAttributes() [models.AttributeSize]byte
		GetQeReportMiscSelect() uint32
		GetQeReportMrSigner() [models.HashSize]byte
		GetEnclaveMrSigner() [models.HashSize]byte
		GetQeReportProdID() uint16
		GetEnclaveReportProdID() uint16
		GetQeReportIsvSvn() uint16
		GetEnclaveReportIsvSvn() uint16
		GetQeReportMrEnclave() [32]byte
		GetEnclaveReportMrEnclave() [32]byte
		DumpSGXQuote()
		GetEnclaveReportSignature() []byte
		GetQeReportSignature() []byte
		GetAttestationPublicKey() []byte
		GetQuotePckCertObj() *x509.Certificate
		GetQuotePckCertInterCAList() []*x509.Certificate
		GetQuotePckCertRootCAList() []*x509.Certificate
		ParseQuoteCerts() error
		ParseRawECDSAQuote(decodedQuote []byte) error
	}

	PCKCertParser interface {
		GenPckCertRequiredExtMap()
		GenPckCertRequiredSgxExtMap()
		GetPckCertRequiredExtMap() map[string]asn1.ObjectIdentifier
		GetPckCertRequiredSgxExtMap() map[string]asn1.ObjectIdentifier
		GenCertObj(certBlob []byte) error
		GetFmspcValue() string
		GetPckCertTcbLevels() []byte
		ParseFMSPCValue() error
		ParseTcbExtensions() error
		GetPCKPublicKey() *ecdsa.PublicKey
		GetPckCrlURL() []string
		GetPckCrlObj() []*pkix.CertificateList
		GetPckCrlInterCaList() []*x509.Certificate
		GetPckCrlRootCaList() []*x509.Certificate
		ParsePckCrl() error
	}

	SGXQuoteVerifier interface {
		SgxEcdsaQuoteVerify(data models.QuoteDataWithChallenge, scsClient HttpClient, config *config.Configuration,
			trustedSGXRootCAFile string) (models.SGXResponse, error)
	}
)
