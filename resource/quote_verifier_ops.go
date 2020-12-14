/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"net/http"
	"strconv"
)

type SGXResponse struct {
	Status                 string
	Message                string
	ChallengeKeyType       string
	ChallengeRsaPublicKey  string
	EnclaveIssuer          string
	EnclaveIssuerProdID    string
	EnclaveIssuerExtProdID string
	EnclaveMeasurement     string
	ConfigSvn              string
	IsvSvn                 string
	ConfigId               string
	TcbLevel               string
}

type SGXQVLResponse struct {
	Message                string
	ReportData             string `json:"reportData"`
	UserDataHashMatch      string `json:"userDataMatch,omitempty"`
	EnclaveIssuer          string
	EnclaveMeasurement     string
	EnclaveIssuerProdID    string
	EnclaveIssuerExtProdID string
	ConfigSvn              string
	IsvSvn                 string
	ConfigId               string
	TcbLevel               string
}

type QuoteData struct {
	QuoteBlob string `json:"quote"`
}

type QVLQuoteData struct {
	QuoteBlob string `json:"quote"`
	UserData  string `json:"userData"`
}

func QuoteVerifyCB(router *mux.Router, conf *config.Configuration) {
	router.Handle("/verifyQuote", handlers.ContentTypeHandler(quoteVerify(conf), "application/json")).Methods("POST")
	router.Handle("/sgx_qv_verify_quote", handlers.ContentTypeHandler(sgx_qv_verify_quote(conf), "application/json")).Methods("POST")
}

func quoteVerify(conf *config.Configuration) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		c := config.Global()
		if c == nil {
			return &resourceError{Message: "could not read config",
				StatusCode: http.StatusInternalServerError}
		}
		if c.IncludeToken == "true" {
			err := AuthorizeEndpoint(r, constants.QuoteVerifierGroupName, true)
			if err != nil {
				return err
			}
		}

		var data QuoteData
		if r.ContentLength == 0 {
			slog.Error("resource/quote_verifier_ops: quoteVerify() The request body was not provided")
			return &resourceError{Message: "sgx ecdsa quote not provided", StatusCode: http.StatusBadRequest}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			slog.WithError(err).Errorf("resource/quote_verifier_ops: quoteVerify() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: "invalid sgx ecdsa quote" + err.Error(),
				StatusCode: http.StatusBadRequest}
		}

		obj := parser.ParseSkcQuoteBlob(data.QuoteBlob)
		if obj == nil {
			return &resourceError{Message: "could not parse sgx ecdsa quote",
				StatusCode: http.StatusBadRequest}
		}

		if obj.GetQuoteType() == parser.QuoteTypeEcdsa {
			return sgxEcdsaQuoteVerify(w, r, obj, conf, "", false)
		} else {
			return &resourceError{Message: "not a sgx ecdsa quote",
				StatusCode: http.StatusBadRequest}
		}
		return nil
	}
}

func sgx_qv_verify_quote(conf *config.Configuration) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/quote_verifier_ops:sgx_qv_verify_quote() Entering")
		defer log.Trace("resource/quote_verifier_ops:sgx_qv_verify_quote() Leaving")

		c := config.Global()
		if c == nil {
			return &resourceError{Message: "could not read config",
				StatusCode: http.StatusInternalServerError}
		}
		if c.IncludeToken == "true" {
			err := AuthorizeEndpoint(r, constants.QuoteVerifierGroupName, true)
			if err != nil {
				return err
			}
		}

		var data QVLQuoteData
		if r.ContentLength == 0 {
			slog.Error("resource/quote_verifier_ops: sgx_qv_verify_quote() The request body was not provided")
			return &resourceError{Message: "SGX_QL_ERROR_INVALID_PARAMETER", StatusCode: http.StatusBadRequest}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			slog.WithError(err).Errorf("resource/quote_verifier_ops: sgx_qv_verify_quote() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: "invalid sgx ecdsa quote" + err.Error(),
				StatusCode: http.StatusBadRequest}
		}

		obj := parser.ParseQVLQuoteBlob(data.QuoteBlob)
		if obj == nil {
			return &resourceError{Message: "could not parse sgx ecdsa quote",
				StatusCode: http.StatusBadRequest}
		}
		return sgxEcdsaQuoteVerify(w, r, obj, conf, data.UserData, true)
	}
}

func sgxEcdsaQuoteVerify(w http.ResponseWriter, r *http.Request, skcBlobParser *parser.SkcBlobParsed,
	conf *config.Configuration, userData string, isQVLVerified bool) error {
	if len(skcBlobParser.GetQuoteBlob()) == 0 {
		return &resourceError{Message: "invalid sgx ecdsa quote length", StatusCode: http.StatusBadRequest}
	}

	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParser.GetQuoteBlob())
	if quoteObj == nil {
		return &resourceError{Message: "invalid sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil {
		return &resourceError{Message: "cannot extract cert pem data: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	certObj := parser.NewPCKCertObj(pckCertBytes)
	if certObj == nil {
		return &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
		quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCrlObj(), conf.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "cannot verify pck cert: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPckCrl(certObj.GetPckCrlUrl(), certObj.GetPckCrlObj(), certObj.GetPckCrlInterCaList(),
		certObj.GetPckCrlRootCaList(), conf.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "cannot verify pck crl: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	tcbObj, err := parser.NewTcbInfo(certObj.GetFmspcValue())
	if err != nil {
		return &resourceError{Message: "Get TCB Info data parsing/fetch failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	err = verifyTcbInfo(certObj, tcbObj, conf.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "TCBInfo Verification failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	tcbUptoDateStatus := tcbObj.GetTcbUptoDateStatus(certObj.GetPckCertTcbLevels())
	log.Info("Current Tcb-Upto-Date Status is : ", tcbUptoDateStatus)

	qeIdObj, err := parser.NewQeIdentity()
	if err != nil {
		return &resourceError{Message: "QEIdentity Parsing failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifyQeIdentity(qeIdObj, quoteObj, conf.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "verifyQeIdentity failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	var rsaBytes []byte
	if !isQVLVerified {
		rsaBytes, err = skcBlobParser.GetRsaPubKey()
		if err != nil {
			return &resourceError{Message: "Cannot extract enclave public key from quote: Error: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}
	}

	hashMatched := false

	if !isQVLVerified {
		_, err = verifier.VerifiySHA256Hash(quoteObj.GetSHA256Hash(), skcBlobParser.GetPubKeyBlob())
		if err != nil {
			log.Error(err.Error())
			return &resourceError{Message: "VerifiySHA256Hash failed: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}
	} else if userData != "" {
		data, err := base64.StdEncoding.DecodeString(userData)
		if err != nil {
			log.Error("Failed to Base64 Decode User Data")
		}
		_, err = verifier.VerifiySHA256Hash(quoteObj.GetSHA256Hash(), []byte(data))
		if err != nil {
			log.Error(err.Error())
		} else {
			hashMatched = true
			log.Info("Hash is matched")
		}
	}

	blob1, err := quoteObj.GetRawBlob1()
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob data in SGX ECDSA Quote: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign1(quoteObj.GetECDSASignature1(), blob1, certObj.GetECDSAPublicKey())
	if err != nil {
		return &resourceError{Message: "SGX ECDSA Signature Verification(1) failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	blob2, err := quoteObj.GetRawBlob2()
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob 2 data in SGX ECDSA Quote: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign2(quoteObj.GetECDSASignature2(), blob2, quoteObj.GetECDSAPublicKey2())
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "SGX ECDSA Signature Verification(2) failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if isQVLVerified {
		w.Header().Set("Content-Type", "application/json")
		var resp SGXQVLResponse
		resp.Message = "SGX_QL_QV_RESULT_OK"
		if userData != "" {
			resp.UserDataHashMatch = strconv.FormatBool(hashMatched)
		}
		resp.ReportData = fmt.Sprintf("%02x", quoteObj.GetSHA256Hash())
		resp.EnclaveIssuer = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrSigner)
		resp.EnclaveIssuerProdID = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvProdId)
		resp.EnclaveIssuerExtProdID = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvextProdId)
		resp.EnclaveMeasurement = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrEnclave)
		resp.ConfigSvn = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxConfigSvn)
		resp.IsvSvn = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvSvn)
		resp.ConfigId = fmt.Sprintf("%02x", quoteObj.Header.ReportBody.ConfigId)
		resp.TcbLevel = tcbUptoDateStatus

		js, err := json.Marshal(resp)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		log.Info("Sgx Ecdsa Quote Verification completed")

	} else {
		res := SGXResponse{
			Status:                 "Success",
			Message:                "SGX ECDSA Quote Verification Successful",
			ChallengeKeyType:       "RSA",
			ChallengeRsaPublicKey:  string(rsaBytes),
			EnclaveIssuer:          fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrSigner),
			EnclaveIssuerProdID:    fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvProdId),
			EnclaveIssuerExtProdID: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvextProdId),
			EnclaveMeasurement:     fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrEnclave),
			ConfigSvn:              fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxConfigSvn),
			IsvSvn:                 fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvSvn),
			ConfigId:               fmt.Sprintf("%02x", quoteObj.Header.ReportBody.ConfigId),
			TcbLevel:               tcbUptoDateStatus,
		}

		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		log.Info("Sgx Ecdsa Quote Verification completed")
	}
	return nil
}

func verifyQeIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed) (bool, error) {
	_, err := verifier.VerifyMiscSelect(quoteObj.GetQeReportMiscSelect(), qeIdObj.GetQeIdMiscSelect(),
		qeIdObj.GetQeIdMiscSelectMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport: ")
	}

	_, err = verifier.VerifyAttributes(quoteObj.GetQeReportAttributes(), qeIdObj.GetQeIdAttributes(),
		qeIdObj.GetQeIdAttributesMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport:")
	}

	_, err = verifier.VerifyReportAttrSize(quoteObj.GetQeReportMrSigner(), "MrSigner", qeIdObj.GetQeIdMrSigner())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport")
	}

	if quoteObj.GetQeReportProdId() < qeIdObj.GetQeIdIsvProdId() {
		log.Info("Qe Prod Id in ecdsa quote is below the minimum prod id expected for QE")
	}

	if quoteObj.GetQeReportIsvSvn() < qeIdObj.GetQeIdIsvSvn() {
		log.Info("IsvSvn in ecdsa quote is below the minimum IsvSvn expected for QE")
	}
	return true, nil
}

func verifyQeIdentity(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed,
	trustedRootCA *x509.Certificate) (bool, error) {

	if qeIdObj == nil || quoteObj == nil {
		return false, errors.New("verifyQeIdentity: QEIdentity/Quote Object is empty")
	}
	_, err := verifier.VerifyQeIdCertChain(qeIdObj.GetQeInfoInterCaList(), qeIdObj.GetQeInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentity: VerifyQeIdCertChain")
	}

	status := qeIdObj.GetQeIdentityStatus()
	if !status {
		return false, errors.New("verifyQeIdentity: GetQeIdentityStatus is invalid")
	}

	if !utils.CheckDate(qeIdObj.GetQeIdIssueDate(), qeIdObj.GetQeIdNextUpdate()) {
		return false, errors.New("verifyQeIdentity: Date Check validation failed")
	}

	return verifyQeIdentityReport(qeIdObj, quoteObj)
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
