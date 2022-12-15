/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	commLogMsg "intel/isecl/lib/common/v5/log/message"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/constants"
	"intel/isecl/sqvs/v5/resource/domain"
	"intel/isecl/sqvs/v5/resource/domain/models"
	"intel/isecl/sqvs/v5/resource/parser"
	"intel/isecl/sqvs/v5/resource/utils"
	"intel/isecl/sqvs/v5/resource/verifier"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type SignedSGXResponse struct {
	QuoteData        string `json:"quoteData"`
	Signature        string `json:"signature,omitempty"`
	CertificateChain string `json:"certificateChain,omitempty"`
}

type UnsignedSGXResponse struct {
	QuoteData QuoteInfo `json:"quoteData"`
}

type QuoteInfo struct {
	ReportData        string `json:"ReportData,omitempty"`
	UserDataHashMatch string `json:"UserDataMatch,omitempty"`
	models.AdditionalQuoteData
}

type SgxQuoteVerifier struct {
	config               *config.Configuration
	scsClient            domain.HttpClient
	trustedSGXRootCAFile string
	SGXQuoteVerifier     domain.SGXQuoteVerifier
}

func NewSGXQuoteVerifier(conf *config.Configuration, scsClient domain.HttpClient, trustedSGXRootCAFile string,
	sgxQuoteVerifier domain.SGXQuoteVerifier) *SgxQuoteVerifier {
	return &SgxQuoteVerifier{
		config:               conf,
		scsClient:            scsClient,
		trustedSGXRootCAFile: trustedSGXRootCAFile,
		SGXQuoteVerifier:     sgxQuoteVerifier,
	}
}

type SgxEcdsaQuoteVerifier struct {
}

func NewSGXEcdsaQuoteVerifier() domain.SGXQuoteVerifier {

	return &SgxEcdsaQuoteVerifier{}
}

func QuoteVerifyCB(router *mux.Router, conf *config.Configuration, scsClient domain.HttpClient,
	trustedSGXRootCAFile string, sgxQuoteVerifier domain.SGXQuoteVerifier) {

	quoteVerifier := NewSGXQuoteVerifier(conf, scsClient, trustedSGXRootCAFile, sgxQuoteVerifier)

	router.Handle("/sgx_qv_verify_quote", handlers.ContentTypeHandler(quoteVerifier.sgxVerifyQuote(), "application/json")).Methods("POST")
}

func (sqv *SgxQuoteVerifier) sgxVerifyQuote() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/quote_verifier_ops:sgxVerifyQuote() Entering")
		defer log.Trace("resource/quote_verifier_ops:sgxVerifyQuote() Leaving")

		if sqv.config.IncludeToken {
			err := AuthorizeEndpoint(r, constants.QuoteVerifierGroupName, true)
			if err != nil {
				slog.WithError(err).Error("resource/quote_verifier_ops: sgxVerifyQuote() Authorization Error")
				return err
			}
		}

		var data models.QuoteData
		if r.ContentLength == 0 {
			slog.Error("resource/quote_verifier_ops: sgxVerifyQuote() The request body was not provided")
			return &resourceError{Message: "SGX_QL_ERROR_INVALID_PARAMETER", StatusCode: http.StatusBadRequest}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			slog.WithError(err).Errorf("resource/quote_verifier_ops: sgxVerifyQuote() %s:Failed to decode "+
				"request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: "Invalid JSON input provided", StatusCode: http.StatusBadRequest}
		}

		if sqv.SGXQuoteVerifier == nil {
			sqv.SGXQuoteVerifier = NewSGXEcdsaQuoteVerifier()
		}

		sgxResponse, err := sqv.SGXQuoteVerifier.SgxEcdsaQuoteVerify(models.QuoteDataWithChallenge{
			QuoteData: data,
		}, sqv.scsClient, sqv.config, sqv.trustedSGXRootCAFile)
		if err != nil {
			return err
		}
		quoteResponseBytes, err := json.Marshal(sgxResponse)
		if err != nil {
			log.WithError(err).Error("Error marshalling SGX response in JSON")
			return &resourceError{Message: "Error marshalling SGX response in JSON", StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(quoteResponseBytes)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}

func (seqv *SgxEcdsaQuoteVerifier) SgxEcdsaQuoteVerify(data models.QuoteDataWithChallenge, scsClient domain.HttpClient, config *config.Configuration,
	trustedSGXRootCAFile string) (models.SGXResponse, error) {
	log.Trace("resource/quote_verifier_ops:SgxEcdsaQuoteVerify() Entering")
	log.Trace("resource/quote_verifier_ops:SgxEcdsaQuoteVerify() Leaving")
	skcBlobParsed := parser.ParseQuoteBlob(data.QuoteBlob)
	if skcBlobParsed == nil {
		log.Error("Could not parse sgx ecdsa quote")
		return models.SGXResponse{}, &resourceError{Message: "Could not parse sgx ecdsa quote",
			StatusCode: http.StatusBadRequest}
	}

	quoteObj := parser.NewSGXQuoteParser(skcBlobParsed.GetQuoteBlob())

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil {
		log.WithError(err).Error("Cannot extract PCK cert data")
		return models.SGXResponse{}, &resourceError{Message: "Cannot extract PCK cert data",
			StatusCode: http.StatusBadRequest}
	}

	certObj := parser.NewPCKCertObj(pckCertBytes, scsClient, config)
	if certObj == nil {
		return models.SGXResponse{}, &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
	}

	sgxCaCert, err := readSGXRootCaCert(trustedSGXRootCAFile)
	if err != nil {
		log.WithError(err).Error("Cannot read SGX CA Cert")
		return models.SGXResponse{}, &resourceError{Message: "Cannot read SGX CA Cert",
			StatusCode: http.StatusBadRequest}
	}

	err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
		quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCrlObj(), sgxCaCert)
	if err != nil {
		log.WithError(err).Error("Cannot verify pck cert")
		return models.SGXResponse{}, &resourceError{Message: "Cannot verify pck cert",
			StatusCode: http.StatusBadRequest}
	}

	log.Info("PCK Certificate Chain Verified")
	err = verifier.VerifyPckCrl(certObj.GetPckCrlURL(), certObj.GetPckCrlObj(), certObj.GetPckCrlInterCaList(),
		certObj.GetPckCrlRootCaList(), sgxCaCert)
	if err != nil {
		log.WithError(err).Error("Cannot verify PCK crl")
		return models.SGXResponse{}, &resourceError{Message: "Cannot verify PCK crl",
			StatusCode: http.StatusBadRequest}
	}

	log.Info("PCK Certificates checked against PCK Certificate Revocation List")
	tcbObj, err := parser.NewTcbInfo(certObj.GetFmspcValue(), config, scsClient)
	if err != nil {
		log.WithError(err).Error("Get TCB Info data parsing/fetch failed")
		return models.SGXResponse{}, &resourceError{Message: "Get TCB Info data parsing/fetch failed",
			StatusCode: http.StatusInternalServerError}
	}

	err = verifyTcbInfo(certObj, tcbObj, sgxCaCert)
	if err != nil {
		log.WithError(err).Error("TCBInfo Verification failed")
		return models.SGXResponse{}, &resourceError{Message: "TCBInfo Verification failed",
			StatusCode: http.StatusInternalServerError}
	}

	log.Info("TCBInfo Structure Verified")
	tcbUptoDateStatus := tcbObj.GetTcbUptoDateStatus(certObj.GetPckCertTcbLevels())
	log.Info("Current Tcb-Upto-Date Status is : ", tcbUptoDateStatus)

	qeIDObj, err := parser.NewQeIdentity(config, scsClient)
	if err != nil {
		log.WithError(err).Error("QEIdentity Parsing failed")
		return models.SGXResponse{}, &resourceError{Message: "QEIdentity Parsing failed",
			StatusCode: http.StatusInternalServerError}
	}

	err = verifyQeIdentity(qeIDObj, quoteObj, sgxCaCert)
	if err != nil {
		log.WithError(err).Error("verifyQeIdentity failed")
		return models.SGXResponse{}, &resourceError{Message: "Verification of QeIdentity failed",
			StatusCode: http.StatusInternalServerError}
	}
	log.Info("QEIdentity Structure Verified")
	hashMatched := false

	if data.UserData != "" {
		data, err := base64.StdEncoding.DecodeString(data.UserData)
		if err != nil {
			log.Error("Failed to Base64 Decode User Data")
		}
		err = verifier.VerifySHA256Hash(quoteObj.GetSHA256Hash(), data)
		if err != nil {
			log.Error(err.Error())
		} else {
			hashMatched = true
			log.Info("User Data Hash matches with the one in quote")
		}
	}

	repBlob, err := quoteObj.GetHeaderAndEnclaveReportBlob()
	if err != nil {
		log.WithError(err).Error("Invalid Header and Enclave Report Blob in SGX ECDSA Quote")
		return models.SGXResponse{}, &resourceError{Message: "Invalid Header and Enclave Report Blob in SGX ECDSA Quote",
			StatusCode: http.StatusInternalServerError}
	}

	err = verifier.VerifyEnclaveReportSignature(quoteObj.GetEnclaveReportSignature(), repBlob, quoteObj.GetAttestationPublicKey())
	if err != nil {
		log.WithError(err).Error("Enclave Report Signature Verification failed")
		return models.SGXResponse{}, &resourceError{Message: "Enclave Report Signature Verification failed",
			StatusCode: http.StatusInternalServerError}
	}

	log.Info("Enclave Report Signature Verified")
	qeBlob, err := quoteObj.GetQeReportBlob()
	if err != nil {
		log.Error(err.Error())
		return models.SGXResponse{}, &resourceError{Message: "Invalid QE Report Blob in SGX ECDSA Quote",
			StatusCode: http.StatusInternalServerError}
	}
	err = verifier.VerifyQeReportSignature(quoteObj.GetQeReportSignature(), qeBlob, certObj.GetPCKPublicKey())
	if err != nil {
		log.WithError(err).Error("QE Report Signature Verification failed")
		return models.SGXResponse{}, &resourceError{Message: "QE Report Signature Verification failed",
			StatusCode: http.StatusInternalServerError}
	}
	log.Info("QE Report Signature Verified")

	var resp models.SGXResponse
	resp.Message = "SGX_QL_QV_RESULT_OK"
	if data.UserData != "" {
		resp.UserDataHashMatch = strconv.FormatBool(hashMatched)
	}
	resp.ReportData = fmt.Sprintf("%02x", quoteObj.GetSHA256Hash())
	resp.EnclaveIssuer = fmt.Sprintf("%02x", quoteObj.GetEnclaveMrSigner())
	resp.EnclaveIssuerProdID = fmt.Sprintf("%02x", quoteObj.GetEnclaveReportProdID())
	resp.EnclaveMeasurement = fmt.Sprintf("%02x", quoteObj.GetEnclaveReportMrEnclave())
	resp.IsvSvn = fmt.Sprintf("%02x", quoteObj.GetEnclaveReportIsvSvn())
	resp.TcbLevel = tcbUptoDateStatus

	log.Info("Sgx Ecdsa Quote Verification completed")

	return resp, nil
}

func verifyQeIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj domain.SGXQuoteParser) error {
	log.Trace("resource/quote_verifier_ops:verifyQeIdentityReport() Entering")
	log.Trace("resource/quote_verifier_ops:verifyQeIdentityReport() Leaving")

	err := verifier.VerifyMiscSelect(quoteObj.GetQeReportMiscSelect(), qeIdObj.GetQeIDMiscSelect(),
		qeIdObj.GetQeIDMiscSelectMask())
	if err != nil {
		return errors.Wrap(err, "verifyQeIdentityReport: ")
	}

	err = verifier.VerifyAttributes(quoteObj.GetQeReportAttributes(), qeIdObj.GetQeIDAttributes(),
		qeIdObj.GetQeIDAttributesMask())
	if err != nil {
		return errors.Wrap(err, "verifyQeIdentityReport:")
	}

	err = verifier.VerifyReportAttrSize(quoteObj.GetQeReportMrSigner(), "MrSigner", qeIdObj.GetQeIDMrSigner())
	if err != nil {
		return errors.Wrap(err, "verifyQeIdentityReport")
	}

	if quoteObj.GetQeReportProdID() < qeIdObj.GetQeIDIsvProdID() {
		log.Info("Qe Prod Id in ecdsa quote is below the minimum prod id expected for QE")
	}

	if quoteObj.GetQeReportIsvSvn() < qeIdObj.GetQeIDIsvSvn() {
		log.Info("IsvSvn in ecdsa quote is below the minimum IsvSvn expected for QE")
	}
	return nil
}

func verifyQeIdentity(qeIDObj *parser.QeIdentityData, quoteObj domain.SGXQuoteParser,
	trustedRootCA *x509.Certificate) error {
	log.Trace("resource/quote_verifier_ops:verifyQeIdentity() Entering")
	log.Trace("resource/quote_verifier_ops:verifyQeIdentity() Leaving")

	if qeIDObj == nil || quoteObj == nil {
		return errors.New("verifyQeIdentity: QEIdentity/Quote Object is empty")
	}
	err := verifier.VerifyQeIDCertChain(qeIDObj.GetQeInfoInterCaList(), qeIDObj.GetQeInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return errors.Wrap(err, "verifyQeIdentity: VerifyQeIDCertChain")
	}

	status := qeIDObj.GetQeIdentityStatus()
	if !status {
		return errors.New("verifyQeIdentity: GetQeIdentityStatus is invalid")
	}

	if !utils.CheckDate(qeIDObj.GetQeIDIssueDate(), qeIDObj.GetQeIDNextUpdate()) {
		return errors.New("verifyQeIdentity: Date Check validation failed")
	}

	return verifyQeIdentityReport(qeIDObj, quoteObj)
}

func verifyTcbInfo(certObj domain.PCKCertParser, tcbObj *parser.TcbInfoStruct, trustedRootCA *x509.Certificate) error {
	log.Trace("resource/quote_verifier_ops:verifyTcbInfo() Entering")
	log.Trace("resource/quote_verifier_ops:verifyTcbInfo() Leaving")

	if tcbObj.GetTcbInfoFmspc() != certObj.GetFmspcValue() {
		return errors.New("verifyTcbInfo: FMSPC in TCBInfoStruct does not match with PCK Cert FMSPC")
	}

	err := verifier.VerifyTcbInfoCertChain(tcbObj.GetTcbInfoInterCaList(), tcbObj.GetTcbInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return errors.Wrap(err, "verifyTcbInfo: failed to verify Tcbinfo Certchain")
	}

	if !utils.CheckDate(tcbObj.GetTcbInfoIssueDate(), tcbObj.GetTcbInfoNextUpdate()) {
		return errors.New("verifyTcbInfo: Date Check validation failed")
	}

	return nil
}

func readSGXRootCaCert(trustedSGXRootCAFile string) (*x509.Certificate, error) {
	log.Trace("resource/quote_verifier_ops:readSGXRootCaCert() Entering")
	log.Trace("resource/quote_verifier_ops:readSGXRootCaCert() Leaving")

	certBytes, err := ioutil.ReadFile(trustedSGXRootCAFile)
	if err != nil {
		return nil, errors.Wrap(err, "readSGXRootCaCert: error reading SGX CA certificate")
	}
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, errors.New("readSGXRootCaCert: Pem Decode error")
	}
	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "readSGXRootCaCert: error parsing SGX CA certificate")
	}

	return x509Cert, nil
}
