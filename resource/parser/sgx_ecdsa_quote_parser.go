/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	clog "intel/isecl/lib/common/v5/log"
	"intel/isecl/sqvs/v5/constants"
	"intel/isecl/sqvs/v5/resource/domain"
	"intel/isecl/sqvs/v5/resource/domain/models"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/restruct.v1"
)

var log = clog.GetDefaultLogger()

type SgxQuoteParsed struct {
	Header             models.QuoteHeader
	EnclaveReport      models.ReportBody
	QuoteSignLen       uint32
	QuoteSignatureData models.QuoteAuthData
	PCKCert            *x509.Certificate
	RootCA             map[string]*x509.Certificate
	InterMediateCA     map[string]*x509.Certificate
}

type SkcBlobParsed struct {
	QuoteBlob []byte
}

func ParseQuoteBlob(rawBlob string) *SkcBlobParsed {
	decodedBlob, err := base64.StdEncoding.DecodeString(rawBlob)
	if err != nil {
		log.Error("Failed to Base64 Decode Quote")
		return nil
	}
	quoteSize := len(decodedBlob)
	if quoteSize < constants.MinQuoteSize || quoteSize > constants.MaxQuoteSize {
		log.Error("Quote Size is invalid. Seems to be an invalid ecdsa quote")
		return nil
	}
	parsedObj := new(SkcBlobParsed)
	parsedObj.QuoteBlob = make([]byte, quoteSize)
	copy(parsedObj.QuoteBlob, decodedBlob)
	return parsedObj
}

func (e *SkcBlobParsed) GetQuoteBlob() []byte {
	return e.QuoteBlob
}

func NewSGXQuoteParser(rawBlob []byte) domain.SGXQuoteParser {
	parsedObj := new(SgxQuoteParsed)
	err := parsedObj.ParseRawECDSAQuote(rawBlob)
	if err != nil {
		log.Error("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote parsing error: ", err.Error())
		return nil
	}
	return parsedObj
}

func ParseEcdsaQuoteBlob(rawBlob []byte) *SgxQuoteParsed {
	parsedObj := new(SgxQuoteParsed)
	err := parsedObj.ParseRawECDSAQuote(rawBlob)
	if err != nil {
		log.Error("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote parsing error: ", err.Error())
		return nil
	}
	return parsedObj
}

func (e *SgxQuoteParsed) GetSHA256Hash() []byte {
	hashValue := make([]byte, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		hashValue[i] = e.EnclaveReport.ReportData[i]
	}
	return hashValue
}

func (e *SgxQuoteParsed) GetQeReportBlob() ([]byte, error) {
	QeReportBlob, err := restruct.Pack(binary.LittleEndian, &e.QuoteSignatureData.QeReport)
	if err != nil {
		log.Error("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetReportBlob: Failed to extract enclave report from quote")
	}

	return QeReportBlob, nil
}

func (e *SgxQuoteParsed) GetHeaderAndEnclaveReportBlob() ([]byte, error) {
	HeaderBlob, err := restruct.Pack(binary.LittleEndian, &e.Header)
	if err != nil {
		log.Error("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetHeaderAndReportBlob: Failed to extract header from quote")
	}
	EnclaveReportBlob, err := restruct.Pack(binary.LittleEndian, &e.EnclaveReport)
	if err != nil {
		log.Error("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetHeaderAndReportBlob: Failed to extract enclave report from quote")
	}

	return append(HeaderBlob, EnclaveReportBlob...), nil
}

func (e *SgxQuoteParsed) GetQeReportAttributes() [models.AttributeSize]byte {
	return e.QuoteSignatureData.QeReport.SgxAttributes
}

func (e *SgxQuoteParsed) GetQeReportMiscSelect() uint32 {
	return e.QuoteSignatureData.QeReport.MiscSelect
}

func (e *SgxQuoteParsed) GetQeReportMrSigner() [models.HashSize]byte {
	return e.QuoteSignatureData.QeReport.MrSigner
}

func (e *SgxQuoteParsed) GetEnclaveMrSigner() [models.HashSize]byte {
	return e.EnclaveReport.MrSigner
}

func (e *SgxQuoteParsed) GetQeReportProdID() uint16 {
	return e.QuoteSignatureData.QeReport.SgxIsvProdID
}

func (e *SgxQuoteParsed) GetEnclaveReportProdID() uint16 {
	return e.EnclaveReport.SgxIsvProdID
}

func (e *SgxQuoteParsed) GetQeReportIsvSvn() uint16 {
	return e.QuoteSignatureData.QeReport.SgxIsvSvn
}

func (e *SgxQuoteParsed) GetEnclaveReportIsvSvn() uint16 {
	return e.EnclaveReport.SgxIsvSvn
}

func (e *SgxQuoteParsed) GetQeReportMrEnclave() [32]byte {
	return e.QuoteSignatureData.QeReport.MrEnclave
}

func (e *SgxQuoteParsed) GetEnclaveReportMrEnclave() [32]byte {
	return e.EnclaveReport.MrEnclave
}

func (e *SgxQuoteParsed) DumpSGXQuote() {
	log.Debug("Version = ", e.Header.Version)
	log.Debug("Attestation Key Type = ", e.Header.AttestationKeyType)
	log.Debug("Tee Type = ", e.Header.TeeType)
	log.Debug("QeSvn = ", e.Header.QeSvn)
	log.Debug("PceSvn = ", e.Header.PceSvn)

	log.Printf("QE Report CPUSvn = %x", e.QuoteSignatureData.QeReport.CPUSvn)
	log.Printf("QE Report MiscSelect = %x", e.QuoteSignatureData.QeReport.MiscSelect)
	log.Printf("QE Report SgxAttributes = %x", e.QuoteSignatureData.QeReport.SgxAttributes)
	log.Printf("QE Report MrEnclave = %x", e.QuoteSignatureData.QeReport.MrEnclave)
	log.Printf("QE Report MrSigner = %x", e.QuoteSignatureData.QeReport.MrSigner)
	log.Printf("QE Report IsvProdID = %x", e.QuoteSignatureData.QeReport.SgxIsvProdID)
	log.Debug("QE Report IsvSvn = ", e.QuoteSignatureData.QeReport.SgxIsvSvn)

	log.Printf("Enclave Report CPUSvn = %x", e.EnclaveReport.CPUSvn)
	log.Printf("Enclave Report MiscSelect = %x", e.EnclaveReport.MiscSelect)
	log.Printf("Enclave Report SgxAttributes = %x", e.EnclaveReport.SgxAttributes)
	log.Printf("Enclave Report MrEnclave = %x", e.EnclaveReport.MrEnclave)
	log.Printf("Enclave Report MrSigner = %x", e.EnclaveReport.MrSigner)
	log.Printf("Enclave Report IsvProdID = %x", e.EnclaveReport.SgxIsvProdID)
	log.Debug("Enclave Report IsvSvn = ", e.EnclaveReport.SgxIsvSvn)

	log.Printf("QE Report Signature = %x", e.QuoteSignatureData.QeReportSignature)
	log.Printf("ECDSA Attestation PublicKey = %x", e.QuoteSignatureData.AttestationPublicKey)
	log.Printf("Enclave Report Signature = %x", e.QuoteSignatureData.EnclaveReportSignature)

	log.Printf("Auth Data Size = %v", e.QuoteSignatureData.QeAuthData.ParsedDataSize)
	log.Printf("Cert Data Type = %v", e.QuoteSignatureData.QeCertData.Type)
	log.Printf("Cert Data Size = %v", e.QuoteSignatureData.QeCertData.ParsedDataSize)
}

func (e *SgxQuoteParsed) GetEnclaveReportSignature() []byte {
	Signature := make([]byte, models.Ecdsa256BitSignatureSize)
	copy(Signature, e.QuoteSignatureData.EnclaveReportSignature[:])
	return Signature
}

func (e *SgxQuoteParsed) GetQeReportSignature() []byte {
	Signature := make([]byte, models.Ecdsa256BitSignatureSize)
	copy(Signature, e.QuoteSignatureData.QeReportSignature[:])
	return Signature
}

func (e *SgxQuoteParsed) GetAttestationPublicKey() []byte {
	attestPublicKey := make([]byte, models.Ecdsa256BitPubkeySize)
	copy(attestPublicKey, e.QuoteSignatureData.AttestationPublicKey[:])
	return attestPublicKey
}

func (e *SgxQuoteParsed) GetQuotePckCertObj() *x509.Certificate {
	return e.PCKCert
}

func (e *SgxQuoteParsed) GetQuotePckCertInterCAList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.InterMediateCA))
	var i int
	for _, v := range e.InterMediateCA {
		interMediateCAArr[i] = v
		i++
	}
	return interMediateCAArr
}

func (e *SgxQuoteParsed) GetQuotePckCertRootCAList() []*x509.Certificate {
	rootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int
	for _, v := range e.RootCA {
		rootCAArr[i] = v
		i++
	}
	return rootCAArr
}

func (e *SgxQuoteParsed) ParseQuoteCerts() error {
	if e.QuoteSignatureData.QeCertData.Type != constants.PCKCertType {
		return errors.New(fmt.Sprintf("Invalid Certificate type in Quote Info: %d", e.QuoteSignatureData.QeCertData.Type))
	}

	certs := strings.SplitAfterN(string(e.QuoteSignatureData.QeCertData.Data), "-----END CERTIFICATE-----",
		strings.Count(string(e.QuoteSignatureData.QeCertData.Data), "-----END CERTIFICATE-----"))

	numCerts := len(certs)
	if numCerts < constants.MinCertsInCertChain {
		return errors.New("ParseQuoteCerts: Cert chain should contain atleast 3 certificates")
	}
	var pckCertCount, intermediateCACount, rootCACount int

	e.RootCA = make(map[string]*x509.Certificate)
	e.InterMediateCA = make(map[string]*x509.Certificate)
	for i := 0; i < numCerts; i++ {
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil {
			return errors.New("ParseQuoteCerts: error while decoding PCK Certchain in Quote")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error("ParseCertificate error: ")
			return errors.Wrap(err, "ParseQuoteCerts: ParseCertificate error")
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Certificate") {
			pckCertCount++
			e.PCKCert = cert
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			rootCACount++
			e.RootCA[cert.Subject.String()] = cert
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Processor CA") ||
			strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Platform CA") {
			intermediateCACount++
			e.InterMediateCA[cert.Subject.String()] = cert
		}
		log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}

	if pckCertCount == 0 || rootCACount == 0 || intermediateCACount == 0 {
		return errors.New(fmt.Sprintf("Quote Certificate Data invalid count: Pck Cert Count:%d, IntermediateCA Count:%d, RootCA Count:%d", pckCertCount, intermediateCACount, rootCACount))
	}

	log.Debug(fmt.Sprintf("Quote Certificate Data Info: Pck Cert Count:%d, IntermediateCA Count:%d, RootCA Count:%d", pckCertCount, intermediateCACount, rootCACount))
	return nil
}

func (e *SgxQuoteParsed) ParseRawECDSAQuote(decodedQuote []byte) error {
	err := restruct.Unpack(decodedQuote[:], binary.LittleEndian, &e.Header)
	if err != nil {
		log.Error("Failed to extract header from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract header from quote")
	}

	// Invoke golang in-built recover() function to recover from the panic
	// recover function will receive the error from out of bound slice access
	// and will prevent the program from crashing
	defer func() {
		if perr := recover(); perr != nil {
			log.Error("ParseRawECDSAQuote: slice out of bound access")
		}
	}()

	// Enclave Report Starts at offset of 48 bytes after the quote header
	encReportStart := 48
	err = restruct.Unpack(decodedQuote[encReportStart:], binary.LittleEndian, &e.EnclaveReport)
	if err != nil {
		log.Error("Failed to extract Enclave Report from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract Enclave Report from quote")
	}

	// Quote Auth Data Starts at offset of Quote Header Size (48 bytes) + Enclave Report Size (384 Bytes) +
	// Quote Signature Data length (4 bytes)
	// Quote Auth Data consists of enclave report, signature for Enclave report, its public key
	// and QE enclave reprt signature
	// Quote Auth Data Size is 576 bytes
	quoteAuthStart := encReportStart + models.EnclaveReportLength + 4
	err = restruct.Unpack(decodedQuote[quoteAuthStart:], binary.LittleEndian, &e.QuoteSignatureData)
	if err != nil {
		log.Error("Failed to extract Quote Signature Data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract Code Signature Data from quote")
	}

	// QE Auth Data Starts after Quote Auth Data (576 Bytes)
	qeAuthStart := quoteAuthStart + 576
	err = restruct.Unpack(decodedQuote[qeAuthStart:], binary.LittleEndian, &e.QuoteSignatureData.QeAuthData)
	if err != nil {
		log.Error("Failed to extract quote auth data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract quote auth data from quote")
	}

	// QE Cert Data Starts after QE Auth Data (34 Bytes)
	qeCertStart := qeAuthStart + 34
	err = restruct.Unpack(decodedQuote[qeCertStart:], binary.LittleEndian, &e.QuoteSignatureData.QeCertData)
	if err != nil {
		log.Error("Failed to extract certification data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract certification data from  quote")
	}

	certDataSize := e.QuoteSignatureData.QeCertData.ParsedDataSize
	if certDataSize < constants.MinCertDataSize || certDataSize > constants.MaxCertDataSize {
		log.Error("Failed to extract certification data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract certification data from  quote")
	}

	// QE Cert Data starts at offset 1046. First two bytes denote Cert type
	// next four bytes denote the size of the certificate chain that follows
	// at offset 1052, the certificate chain starts
	certChainStart := qeCertStart + 6
	e.QuoteSignatureData.QeCertData.Data = make([]byte, e.QuoteSignatureData.QeCertData.ParsedDataSize)
	copy(e.QuoteSignatureData.QeCertData.Data, decodedQuote[certChainStart:])

	err = e.ParseQuoteCerts()
	if err != nil {
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to Parse PCK certificates in Quote")
	}
	return nil
}
