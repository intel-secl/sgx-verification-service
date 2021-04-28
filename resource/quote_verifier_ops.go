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
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/sqvs/v3/config"
	"intel/isecl/sqvs/v3/constants"
	"intel/isecl/sqvs/v3/resource/parser"
	"intel/isecl/sqvs/v3/resource/utils"
	"intel/isecl/sqvs/v3/resource/verifier"
	"io/ioutil"
	"net/http"
	"strconv"
)

type SGXResponse struct {
	Message                string
	ReportData             string `json:"reportData,omitempty"`
	UserDataHashMatch      string `json:"userDataMatch,omitempty"`
	EnclaveIssuer          string `json:"EnclaveIssuer,omitempty"`
	EnclaveMeasurement     string `json:"EnclaveMeasurement,omitempty"`
	EnclaveIssuerProdID    string `json:"EnclaveIssuerProdID,omitempty"`
	EnclaveIssuerExtProdID string `json:"EnclaveIssuerExtProdID,omitempty"`
	ConfigSvn              string `json:"ConfigSvn,omitempty"`
	IsvSvn                 string `json:"IsvSvn,omitempty"`
	ConfigID               string `json:"ConfigID,omitempty"`
	TcbLevel               string `json:"TcbLevel,omitempty"`
	Quote                  string `json:"Quote,omitempty"`
	Challenge              string `json:"Challenge,omitempty"`
}

type SignedSGXResponse struct {
	QuoteData        SGXResponse `json:"quoteData"`
	Signature        string      `json:"signature,omitempty"`
	CertificateChain string      `json:"certificateChain,omitempty"`
}

type QuoteData struct {
	QuoteBlob string `json:"quote"`
	UserData  string `json:"userData"`
}

type QuoteDataWithChallenge struct {
	QuoteData
	Challenge string `json:"challenge"`
	//For future use
	Nonce string `json:"nonce"`
}

func QuoteVerifyCB(router *mux.Router) {
	router.Handle("/sgx_qv_verify_quote", handlers.ContentTypeHandler(sgxVerifyQuote(), "application/json")).Methods("POST")
}

func sgxVerifyQuote() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/quote_verifier_ops:sgxVerifyQuote() Entering")
		defer log.Trace("resource/quote_verifier_ops:sgxVerifyQuote() Leaving")

		conf := config.Global()
		if conf == nil {
			return &resourceError{Message: "Could not read config", StatusCode: http.StatusInternalServerError}
		}
		if conf.IncludeToken == true {
			err := AuthorizeEndpoint(r, constants.QuoteVerifierGroupName, true)
			if err != nil {
				slog.WithError(err).Error("resource/quote_verifier_ops: sgxVerifyQuote() Authorization Error")
				return err
			}
		}

		var data QuoteData
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

		sgxResponse, err := SgxEcdsaQuoteVerify(QuoteDataWithChallenge{
			QuoteData: data,
		})
		if err != nil {
			return err
		}
		quoteResponseBytes, err := json.Marshal(sgxResponse)
		if err != nil {
			log.WithError(err).Error("Error marshalling SGX response in JSON")
			return &resourceError{Message: "Error marshalling SGX response in JSON", StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(quoteResponseBytes)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		return nil
	}
}

func SgxEcdsaQuoteVerify(data QuoteDataWithChallenge) (SGXResponse, error) {

	skcBlobParsed := parser.ParseQuoteBlob(data.QuoteBlob)
	if skcBlobParsed == nil {
		log.Error("Could not parse sgx ecdsa quote")
		return SGXResponse{}, &resourceError{Message: "Could not parse sgx ecdsa quote",
			StatusCode: http.StatusBadRequest}
	}

	if len(skcBlobParsed.GetQuoteBlob()) == 0 {
		log.Error("Invalid sgx ecdsa quote length")
		return SGXResponse{}, &resourceError{Message: "Invalid sgx ecdsa quote length", StatusCode: http.StatusBadRequest}
	}

	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParsed.GetQuoteBlob())
	if quoteObj == nil {
		log.Error("Cannot parse sgx ecdsa quote")
		return SGXResponse{}, &resourceError{Message: "Cannot parse sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil {
		log.WithError(err).Error("Cannot extract PCK cert data")
		return SGXResponse{}, &resourceError{Message: "Cannot extract PCK cert data",
			StatusCode: http.StatusBadRequest}
	}

	certObj := parser.NewPCKCertObj(pckCertBytes)
	if certObj == nil {
		return SGXResponse{}, &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
	}

	sgxCaCert, err := readSGXRootCaCert()
	if err != nil {
		log.WithError(err).Error("Cannot read SGX CA Cert")
		return SGXResponse{}, &resourceError{Message: "Cannot read SGX CA Cert",
			StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
		quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCrlObj(), sgxCaCert)
	if err != nil {
		log.WithError(err).Error("Cannot verify pck cert")
		return SGXResponse{}, &resourceError{Message: "Cannot verify pck cert",
			StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPckCrl(certObj.GetPckCrlURL(), certObj.GetPckCrlObj(), certObj.GetPckCrlInterCaList(),
		certObj.GetPckCrlRootCaList(), sgxCaCert)
	if err != nil {
		log.WithError(err).Error("Cannot verify PCK crl")
		return SGXResponse{}, &resourceError{Message: "Cannot verify PCK crl",
			StatusCode: http.StatusBadRequest}
	}

	tcbObj, err := parser.NewTcbInfo(certObj.GetFmspcValue())
	if err != nil {
		log.WithError(err).Error("Get TCB Info data parsing/fetch failed")
		return SGXResponse{}, &resourceError{Message: "Get TCB Info data parsing/fetch failed",
			StatusCode: http.StatusInternalServerError}
	}

	err = verifyTcbInfo(certObj, tcbObj, sgxCaCert)
	if err != nil {
		log.WithError(err).Error("TCBInfo Verification failed")
		return SGXResponse{}, &resourceError{Message: "TCBInfo Verification failed",
			StatusCode: http.StatusInternalServerError}
	}

	tcbUptoDateStatus := tcbObj.GetTcbUptoDateStatus(certObj.GetPckCertTcbLevels())
	log.Info("Current Tcb-Upto-Date Status is : ", tcbUptoDateStatus)

	qeIDObj, err := parser.NewQeIdentity()
	if err != nil {
		log.WithError(err).Error("QEIdentity Parsing failed")
		return SGXResponse{}, &resourceError{Message: "QEIdentity Parsing failed",
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifyQeIdentity(qeIDObj, quoteObj, sgxCaCert)
	if err != nil {
		log.WithError(err).Error("verifyQeIdentity failed")
		return SGXResponse{}, &resourceError{Message: "Verification of QeIdentity failed",
			StatusCode: http.StatusInternalServerError}
	}
	hashMatched := false

	if data.UserData != "" {
		data, err := base64.StdEncoding.DecodeString(data.UserData)
		if err != nil {
			log.Error("Failed to Base64 Decode User Data")
		}
		_, err = verifier.VerifySHA256Hash(quoteObj.GetSHA256Hash(), data)
		if err != nil {
			log.Error(err.Error())
		} else {
			hashMatched = true
			log.Info("User Data Hash matches with the one in quote")
		}
	}

	blob1, err := quoteObj.GetRawBlob1()
	if err != nil {
		log.Error(err.Error())
		return SGXResponse{}, &resourceError{Message: "Invalid Raw Blob data in SGX ECDSA Quote",
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign1(quoteObj.GetECDSASignature1(), blob1, certObj.GetECDSAPublicKey())
	if err != nil {
		log.WithError(err).Error("SGX ECDSA Signature Verification(1) failed")
		return SGXResponse{}, &resourceError{Message: "SGX ECDSA Signature Verification(1) failed",
			StatusCode: http.StatusInternalServerError}
	}
	blob2, err := quoteObj.GetRawBlob2()
	if err != nil {
		log.WithError(err).Error("Invalid Raw Blob 2 data in SGX ECDSA Quote")
		return SGXResponse{}, &resourceError{Message: "Invalid Raw Blob 2 data in SGX ECDSA Quote",
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign2(quoteObj.GetECDSASignature2(), blob2, quoteObj.GetECDSAPublicKey2())
	if err != nil {
		log.WithError(err).Error("SGX ECDSA Signature Verification(2) failed")
		return SGXResponse{}, &resourceError{Message: "SGX ECDSA Signature Verification(2) failed",
			StatusCode: http.StatusInternalServerError}
	}

	var resp SGXResponse
	resp.Message = "SGX_QL_QV_RESULT_OK"
	if data.UserData != "" {
		resp.UserDataHashMatch = strconv.FormatBool(hashMatched)
	}
	resp.ReportData = fmt.Sprintf("%02x", quoteObj.GetSHA256Hash())
	resp.EnclaveIssuer = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrSigner)
	resp.EnclaveIssuerProdID = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvProdID)
	resp.EnclaveIssuerExtProdID = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvextProdID)
	resp.EnclaveMeasurement = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrEnclave)
	resp.ConfigSvn = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxConfigSvn)
	resp.IsvSvn = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvSvn)
	resp.ConfigID = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.ConfigID)
	resp.TcbLevel = tcbUptoDateStatus

	log.Info("Sgx Ecdsa Quote Verification completed")

	return resp, nil
}

func verifyQeIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed) (bool, error) {
	_, err := verifier.VerifyMiscSelect(quoteObj.GetQeReportMiscSelect(), qeIdObj.GetQeIDMiscSelect(),
		qeIdObj.GetQeIDMiscSelectMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport: ")
	}

	_, err = verifier.VerifyAttributes(quoteObj.GetQeReportAttributes(), qeIdObj.GetQeIDAttributes(),
		qeIdObj.GetQeIDAttributesMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport:")
	}

	_, err = verifier.VerifyReportAttrSize(quoteObj.GetQeReportMrSigner(), "MrSigner", qeIdObj.GetQeIDMrSigner())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport")
	}

	if quoteObj.GetQeReportProdID() < qeIdObj.GetQeIDIsvProdID() {
		log.Info("Qe Prod Id in ecdsa quote is below the minimum prod id expected for QE")
	}

	if quoteObj.GetQeReportIsvSvn() < qeIdObj.GetQeIDIsvSvn() {
		log.Info("IsvSvn in ecdsa quote is below the minimum IsvSvn expected for QE")
	}
	return true, nil
}

func verifyQeIdentity(qeIDObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed,
	trustedRootCA *x509.Certificate) (bool, error) {

	if qeIDObj == nil || quoteObj == nil {
		return false, errors.New("verifyQeIdentity: QEIdentity/Quote Object is empty")
	}
	_, err := verifier.VerifyQeIDCertChain(qeIDObj.GetQeInfoInterCaList(), qeIDObj.GetQeInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentity: VerifyQeIDCertChain")
	}

	status := qeIDObj.GetQeIdentityStatus()
	if !status {
		return false, errors.New("verifyQeIdentity: GetQeIdentityStatus is invalid")
	}

	if !utils.CheckDate(qeIDObj.GetQeIDIssueDate(), qeIDObj.GetQeIDNextUpdate()) {
		return false, errors.New("verifyQeIdentity: Date Check validation failed")
	}

	return verifyQeIdentityReport(qeIDObj, quoteObj)
}

func verifyTcbInfo(certObj *parser.PckCert, tcbObj *parser.TcbInfoStruct, trustedRootCA *x509.Certificate) error {
	if tcbObj.GetTcbInfoFmspc() != certObj.GetFmspcValue() {
		return errors.New("verifyTcbInfo: FMSPC in TCBInfoStruct does not match with PCK Cert FMSPC")
	}

	_, err := verifier.VerifyTcbInfoCertChain(tcbObj.GetTcbInfoInterCaList(), tcbObj.GetTcbInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return errors.Wrap(err, "verifyTcbInfo: failed to verify Tcbinfo Certchain")
	}

	if !utils.CheckDate(tcbObj.GetTcbInfoIssueDate(), tcbObj.GetTcbInfoNextUpdate()) {
		return errors.New("verifyTcbInfo: Date Check validation failed")
	}

	return nil
}

func readSGXRootCaCert() (*x509.Certificate, error) {
	log.Trace("resource/quote_verifier_ops:readSGXRootCaCert() Entering")
	log.Trace("resource/quote_verifier_ops:readSGXRootCaCert() Leaving")

	certBytes, err := ioutil.ReadFile(constants.TrustedSGXRootCAFile)
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
