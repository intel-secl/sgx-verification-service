/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/restruct.v1"
	clog "intel/isecl/lib/common/v3/log"
	"intel/isecl/sqvs/v3/constants"
	"strings"
	"unsafe"
)

var log = clog.GetDefaultLogger()

const (
	SgxReportBodyReserved1Bytes      = 12
	SgxReportBodyReserved2Bytes      = 32
	SgxReportBodyReserved3Bytes      = 32
	SgxReportBodyReserved4Bytes      = 42
	SgxIsvextProdIdSize              = 16
	SgxIsvFamilyIdSize               = 16
	SgxReportDataSize                = 64
	SgxEpidGroupIdsize               = 4
	SgxBaseNamesize                  = 32
	SgxConfigIdSize                  = 64
	SgxCpusvnSize                    = 16
	SgxHashSize                      = 32
	QuoteReservedBytes               = 4
	QuoteHeaderUuidSize              = 16
	QuoteHeaderUserDataSize          = 20
	QuoteReserved1Bytes              = 28
	QuoteReserved2Bytes              = 32
	QuoteReserved3Bytes              = 96
	QuoteReserved4Bytes              = 60
	QuoteEnclaveReportCpuSvnSize     = 16
	QuoteEnclaveReportAttributesSize = 16
	QuoteEnclaveReportMrEnclaveSize  = 32
	QuoteEnclaveReportMrSignerSize   = 32
	QuoteEnclaveReportDataSize       = 64
	QuoteEcdsa256BitSignatureSize    = 64
	QuoteEcdsa256BitPubkeySize       = 64
)

// Nested Structure of SgxQuote
type BaseNameT struct {
	Name [SgxBaseNamesize]uint8
}

// Ecdsa Structure sequence - 1
type SgxQuote struct {
	Version      uint16                    /* 0   */
	SignType     uint16                    /* 2   */
	EpidGroupId  [SgxEpidGroupIdsize]uint8 /* 4   */
	QeSvn        uint16                    /* 8   */
	PceSvn       uint16                    /* 10  */
	Xeid         uint32                    /* 12  */
	BaseName     BaseNameT                 /* 48  */
	ReportBody   ReportBodyT
	SignatureLen uint32 /* 432 */
	Signature    []byte
}

// Nested Structure of SgxQuote
type ReportBodyT struct {
	CpuSvn          [SgxCpusvnSize]uint8               /* (0) Security Version of the CPU */
	MiscSelect      uint32                             /* (16) Which fields defined in SSA.MISC */
	Reserved1       [SgxReportBodyReserved1Bytes]uint8 /* (20) */
	SgxIsvextProdId [SgxIsvextProdIdSize]uint8         /* (32) ISV assigned Extended Product ID */
	SgxAttributes   struct {                           /* (48) Any special Capabilities the Enclave possess */
		Flags uint64
		Xfrm  uint64
	}
	MrEnclave      [SgxHashSize]uint8                 /* (64) The value of the enclave's ENCLAVE measurement */
	Reserved2      [SgxReportBodyReserved2Bytes]uint8 /* (96) */
	MrSigner       [SgxHashSize]uint8                 /* (128) The value of the enclave's SIGNER measurement */
	Reserved3      [SgxReportBodyReserved3Bytes]uint8 /* (160) */
	ConfigId       [SgxConfigIdSize]uint8             /* (192) CONFIGID */
	SgxIsvProdId   uint16                             /* (256) Product ID of the Enclave */
	SgxIsvSvn      uint16                             /* (258) Security Version of the Enclave */
	SgxConfigSvn   uint16                             /* (260) CONFIGSVN */
	Reserved4      [SgxReportBodyReserved4Bytes]uint8 /* (262) */
	SgxIsvFamilyId [SgxIsvFamilyIdSize]uint8          /* (304) ISV assigned Family ID */
	SgxReportData  [SgxReportDataSize]uint8           /* (320) Data provided by the user */
}

// Ecdsa Structure sequence - 2
type SgxEcdsaSignatureData struct {
	Signature           [64]uint8
	PublicKey           [64]uint8
	ReportBody          ReportBodyT
	ReportSignature     [64]uint8
	AuthCertificateData []uint8 // 3588
}

// Ecdsa Structure sequence - 3
type QeAuthData struct {
	ParsedDataSize uint16
	Data           []byte
}

// Ecdsa Structure sequence - 4
type QeCertData struct {
	Type           uint16
	ParsedDataSize uint32
	Data           []byte
}

type SgxQuoteParsed struct {
	Header                SgxQuote
	Ecdsa256SignatureData SgxEcdsaSignatureData
	QuoteAuthData         QeAuthData
	QuoteCertData         QeCertData
	RawQuoteFull          []byte
	RawQuoteLen           int
	EcdsaBlob1            []byte
	EcdsaBlob2            []byte
	PCKCert               *x509.Certificate
	RootCA                map[string]*x509.Certificate
	InterMediateCA        map[string]*x509.Certificate
}

func ParseEcdsaQuoteBlob(rawBlob []byte) *SgxQuoteParsed {
	if len(rawBlob) < int(unsafe.Sizeof(SgxQuoteParsed{})) {
		log.Error("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote is Empty: ")
		return nil
	}
	parsedObj := new(SgxQuoteParsed)
	_, err := parsedObj.parseRawECDSAQuote(rawBlob)
	if err != nil {
		log.Error("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote parsing error: ", err.Error())
		return nil
	}
	return parsedObj
}

func (e *SgxQuoteParsed) GetRawBlob1() ([]byte, error) {
	var err error
	blobLen := len(e.EcdsaBlob1)
	if blobLen < 1 {
		return nil, errors.Wrap(err, "GetRawBlob1: Invalid Raw Blob1 Len")
	}
	blob1 := make([]byte, len(e.EcdsaBlob1))
	copy(blob1, e.EcdsaBlob1)
	return blob1, nil
}

func (e *SgxQuoteParsed) GetSHA256Hash() []byte {
	hashValue := make([]byte, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		hashValue[i] = e.Header.ReportBody.SgxReportData[i]
	}
	return hashValue
}

func (e *SgxQuoteParsed) generateRawBlob2() error {
	var err error
	var rawBlobSize2 = 48 + int(unsafe.Sizeof(ReportBodyT{}))
	if e.RawQuoteFull == nil || len(e.RawQuoteFull) < rawBlobSize2 {
		return errors.Wrap(err, "generateRawBlob2: Invalid raw blob2 data")
	}
	e.EcdsaBlob2 = make([]byte, rawBlobSize2)
	for i := 0; i < rawBlobSize2; i++ {
		e.EcdsaBlob2[i] = e.RawQuoteFull[i]
	}
	return nil
}

func (e *SgxQuoteParsed) generateRawBlob1() error {
	var offset int
	report := e.Ecdsa256SignatureData.ReportBody
	e.EcdsaBlob1 = make([]byte, unsafe.Sizeof(ReportBodyT{}))

	for i := 0; i < len(report.CpuSvn); i++ {
		e.EcdsaBlob1[offset] = report.CpuSvn[i]
		offset++
	}

	miscSelectArr := make([]byte, 4)
	binary.LittleEndian.PutUint32(miscSelectArr, report.MiscSelect)

	for i := 0; i < len(miscSelectArr); i++ {
		e.EcdsaBlob1[offset] = miscSelectArr[i]
		offset++
	}

	for i := 0; i < len(report.Reserved1); i++ {
		e.EcdsaBlob1[offset] = report.Reserved1[i]
		offset++
	}

	for i := 0; i < len(report.SgxIsvextProdId); i++ {
		e.EcdsaBlob1[offset] = report.SgxIsvextProdId[i]
		offset++
	}

	sgxAttrFlagsArr := make([]byte, 8)
	binary.LittleEndian.PutUint64(sgxAttrFlagsArr, report.SgxAttributes.Flags)

	for i := 0; i < len(sgxAttrFlagsArr); i++ {
		e.EcdsaBlob1[offset] = sgxAttrFlagsArr[i]
		offset++
	}

	sgxAttrXfrmArr := make([]byte, 8)
	binary.LittleEndian.PutUint64(sgxAttrXfrmArr, report.SgxAttributes.Xfrm)

	for i := 0; i < len(sgxAttrXfrmArr); i++ {
		e.EcdsaBlob1[offset] = sgxAttrXfrmArr[i]
		offset++
	}

	for i := 0; i < len(report.MrEnclave); i++ {
		e.EcdsaBlob1[offset] = report.MrEnclave[i]
		offset++
	}

	for i := 0; i < len(report.Reserved2); i++ {
		e.EcdsaBlob1[offset] = report.Reserved2[i]
		offset++
	}

	for i := 0; i < len(report.MrSigner); i++ {
		e.EcdsaBlob1[offset] = report.MrSigner[i]
		offset++
	}

	for i := 0; i < len(report.Reserved3); i++ {
		e.EcdsaBlob1[offset] = report.Reserved3[i]
		offset++
	}

	for i := 0; i < len(report.ConfigId); i++ {
		e.EcdsaBlob1[offset] = report.ConfigId[i]
		offset++
	}

	sgxIsvProdIdArr := make([]byte, 2)
	binary.LittleEndian.PutUint16(sgxIsvProdIdArr, report.SgxIsvProdId)

	for i := 0; i < len(sgxIsvProdIdArr); i++ {
		e.EcdsaBlob1[offset] = sgxIsvProdIdArr[i]
		offset++
	}

	sgxIsvSvnArr := make([]byte, 2)
	binary.LittleEndian.PutUint16(sgxIsvSvnArr, report.SgxIsvSvn)

	for i := 0; i < len(sgxIsvSvnArr); i++ {
		e.EcdsaBlob1[offset] = sgxIsvSvnArr[i]
		offset++
	}

	sgxConfigSvnArr := make([]byte, 2)
	binary.LittleEndian.PutUint16(sgxConfigSvnArr, report.SgxConfigSvn)

	for i := 0; i < len(sgxConfigSvnArr); i++ {
		e.EcdsaBlob1[offset] = sgxConfigSvnArr[i]
		offset++
	}

	for i := 0; i < len(report.Reserved4); i++ {
		e.EcdsaBlob1[offset] = report.Reserved4[i]
		offset++
	}

	for i := 0; i < len(report.SgxIsvFamilyId); i++ {
		e.EcdsaBlob1[offset] = report.SgxIsvFamilyId[i]
		offset++
	}

	for i := 0; i < len(report.SgxReportData); i++ {
		e.EcdsaBlob1[offset] = report.SgxReportData[i]
		offset++
	}
	return nil
}

func (e *SgxQuoteParsed) GetRawBlob2() ([]byte, error) {
	var err error
	blobLen := len(e.EcdsaBlob2)
	if blobLen < 1 {
		return nil, errors.Wrap(err, "GetRawBlob2: zero len blob2")
	}
	blob2 := make([]byte, len(e.EcdsaBlob2))
	copy(blob2, e.EcdsaBlob2)
	return blob2, nil
}

func (e *SgxQuoteParsed) GetQeReportAttributes() [2]uint64 {
	report := e.Ecdsa256SignatureData.ReportBody.SgxAttributes
	reportAttributes := [2]uint64{}
	reportAttributes[0] = report.Flags
	reportAttributes[1] = report.Xfrm
	return reportAttributes
}

func (e *SgxQuoteParsed) GetQeReportMiscSelect() uint32 {
	return e.Ecdsa256SignatureData.ReportBody.MiscSelect
}

func (e *SgxQuoteParsed) GetQeReportMrSigner() [SgxHashSize]uint8 {
	return e.Ecdsa256SignatureData.ReportBody.MrSigner
}

func (e *SgxQuoteParsed) GetQeReportProdId() uint16 {
	return e.Ecdsa256SignatureData.ReportBody.SgxIsvProdId
}

func (e *SgxQuoteParsed) GetQeReportIsvSvn() uint16 {
	return e.Ecdsa256SignatureData.ReportBody.SgxIsvSvn
}

func (e *SgxQuoteParsed) DumpSGXQuote() {
	log.Debug("Version = ", e.Header.Version)
	log.Debug("SignType = ", e.Header.SignType)
	log.Debug("EpidGroupId = ", e.Header.EpidGroupId)
	log.Debug("QeSvn = ", e.Header.QeSvn)
	log.Debug("PceSvn = ", e.Header.PceSvn)
	log.Debug("Xeid = ", e.Header.Xeid)
	log.Printf("BaseName = %x", e.Header.BaseName)
	log.WithField("BaseName", e.Header.BaseName).Info()
	log.Printf("ReportBody.MrEnclave = %x", e.Header.ReportBody.MrEnclave)
	log.Printf("ReportBody.MrSigner = %x", e.Header.ReportBody.MrSigner)
	log.Printf("ReportBody.ConfigId = %x", e.Header.ReportBody.ConfigId)
	log.Printf("ReportBody.SgxIsvProdId = %x", e.Header.ReportBody.SgxIsvProdId)
	log.Debug("ReportBody.SgxIsvSvn = ", e.Header.ReportBody.SgxIsvSvn)
	log.Debug("ReportBody.SgxIsvFamilyId = ", e.Header.ReportBody.SgxIsvFamilyId)
	log.Printf("ReportBody.CpuSvn = %x", e.Header.ReportBody.CpuSvn)
	log.Printf("ReportBody.MiscSelect = %x", e.Header.ReportBody.MiscSelect)
	log.Printf("ReportBody.SgxAttributes.Flags = %x", e.Header.ReportBody.SgxAttributes.Flags)
	log.Printf("ReportBody.SgxAttributes.Xfrm = %x", e.Header.ReportBody.SgxAttributes.Xfrm)
	log.Printf("SignatureLen= %d", e.Header.SignatureLen)
	log.Printf("Signature= %v", e.Header.Signature)
	log.Printf("Ecdsa256SignatureData.Signature= %x", e.Ecdsa256SignatureData.Signature)
	log.Printf("Ecdsa256SignatureData.PublicKey= %x", e.Ecdsa256SignatureData.PublicKey)
	log.Printf("Ecdsa256SignatureData.MrEnclave = %x", e.Ecdsa256SignatureData.ReportBody.MrEnclave)
	log.Printf("Ecdsa256SignatureData.MrSigner = %x", e.Ecdsa256SignatureData.ReportBody.MrSigner)
	log.Printf("Ecdsa256SignatureData.ConfigId = %x", e.Ecdsa256SignatureData.ReportBody.ConfigId)
	log.Printf("Ecdsa256SignatureData.SgxIsvProdId = %x", e.Ecdsa256SignatureData.ReportBody.SgxIsvProdId)
	log.Debug("Ecdsa256SignatureData.SgxIsvSvn = ", e.Ecdsa256SignatureData.ReportBody.SgxIsvSvn)
	log.Debug("Ecdsa256SignatureData.SgxIsvFamilyId = ", e.Ecdsa256SignatureData.ReportBody.SgxIsvFamilyId)
	log.Printf("Ecdsa256SignatureData.CpuSvn = %x", e.Ecdsa256SignatureData.ReportBody.CpuSvn)
	log.Printf("Ecdsa256SignatureData.MiscSelect = %x", e.Ecdsa256SignatureData.ReportBody.MiscSelect)
	log.Printf("Ecdsa256SignatureData.SgxAttributes.Flags = %x", e.Ecdsa256SignatureData.ReportBody.SgxAttributes.Flags)
	log.Printf("Ecdsa256SignatureData.SgxAttributes.Xfrm = %x", e.Ecdsa256SignatureData.ReportBody.SgxAttributes.Xfrm)
	log.Printf("AuthdataSize = %v", e.QuoteAuthData.ParsedDataSize)
	log.Printf("CertType = %v", e.QuoteCertData.Type)
	log.Printf("CertDat = %v", string(e.QuoteCertData.Data))
}

func (e *SgxQuoteParsed) GetECDSASignature1() []byte {
	Signature1 := make([]byte, len(e.Ecdsa256SignatureData.ReportSignature))
	copy(Signature1, e.Ecdsa256SignatureData.ReportSignature[:])
	return Signature1
}

func (e *SgxQuoteParsed) GetECDSASignature2() []byte {
	Signature2 := make([]byte, len(e.Ecdsa256SignatureData.Signature))
	copy(Signature2, e.Ecdsa256SignatureData.Signature[:])
	return Signature2
}

func (e *SgxQuoteParsed) GetECDSAPublicKey2() []byte {
	PublicKey2 := make([]byte, len(e.Ecdsa256SignatureData.PublicKey))
	copy(PublicKey2, e.Ecdsa256SignatureData.PublicKey[:])
	return PublicKey2
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

func (e *SgxQuoteParsed) parseQuoteCerts() error {
	if e.QuoteCertData.Type != constants.PCKCertType {
		return errors.New(fmt.Sprintf("Invalid Certificate type in Quote Info: %d", e.QuoteCertData.Type))
	}

	certs := strings.SplitAfterN(string(e.QuoteCertData.Data), "-----END CERTIFICATE-----",
		strings.Count(string(e.QuoteCertData.Data), "-----END CERTIFICATE-----"))

	var pckCertCount int
	var intermediateCACount int
	var rootCACount int

	e.RootCA = make(map[string]*x509.Certificate)
	e.InterMediateCA = make(map[string]*x509.Certificate)
	for i := 0; i < len(certs); i++ {
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil {
			return errors.New("parseQuoteCerts: error while decoding PCK Certchain in Quote")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error("ParseCertificate error: ")
			return errors.Wrap(err, "parseQuoteCerts: ParseCertificate error")
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

func (e *SgxQuoteParsed) parseRawECDSAQuote(decodedQuote []byte) (bool, error) {
	e.RawQuoteFull = make([]byte, len(decodedQuote))
	e.RawQuoteLen = len(decodedQuote)
	copy(e.RawQuoteFull, decodedQuote)

	err := restruct.Unpack(e.RawQuoteFull, binary.LittleEndian, &e.Header)
	if err != nil {
		log.Error("Failed to extract header from quote")
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to extract header from quote")
	}

	log.Debug("Version = ", e.Header.Version)
	log.Debug("SignType = ", e.Header.SignType)

	// invoke golang in-built recover() function to recover from the panic
	// recover function will receive the error from out of bound slice access
	// and will prevent the program from crashing
	defer func() {
		if perr := recover(); perr != nil {
			log.Error("parseRawECDSAQuote: slice out of bound access")
		}
	}()

	err = restruct.Unpack(decodedQuote[436:], binary.LittleEndian, &e.Ecdsa256SignatureData)
	if err != nil {
		log.Error("Failed to extract ecdsa signature from quote")
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to extract ecdsa signature from quote")
	}

	err = e.generateRawBlob1()
	if err != nil {
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to generate RawBlob1")
	}

	err = e.generateRawBlob2()
	if err != nil {
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to generate RawBlob2")
	}
	err = restruct.Unpack(decodedQuote[1012:], binary.LittleEndian, &e.QuoteAuthData)
	if err != nil {
		log.Error("Failed to extract quote auth data from quote")
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to extract quote auth data from quote")
	}

	err = restruct.Unpack(decodedQuote[1046:], binary.LittleEndian, &e.QuoteCertData)
	if err != nil {
		log.Error("Failed to extract certification data from quote")
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to extract certification data from  quote")
	}
	e.QuoteCertData.Data = make([]byte, e.QuoteCertData.ParsedDataSize)
	copy(e.QuoteCertData.Data, decodedQuote[1052:])

	err = e.parseQuoteCerts()
	if err != nil {
		return false, errors.Wrap(err, "parseRawECDSAQuote: Failed to Parse PCK certificates in Quote")
	}
	return true, nil
}
