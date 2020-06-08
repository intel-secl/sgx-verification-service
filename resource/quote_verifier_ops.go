/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"intel/isecl/svs/config"
	"intel/isecl/svs/resource/parser"
	"intel/isecl/svs/resource/utils"
	"intel/isecl/svs/resource/verifier"
	"net/http"
)

type SwResponse struct {
	Status                string
	Message               string
	SwIssuer              string
	ChallengeKeyType      string
	ChallengeRsaPublicKey string
}

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

type QuoteData struct {
	QuoteBlob string `json:"quote"`
}

func QuoteVerifyCB(router *mux.Router, config *config.Configuration) {
	router.Handle("/verifyQuote", handlers.ContentTypeHandler(GenericQuoteVerifyCB(config), "application/json")).Methods("POST")
	router.Handle("/push", handlers.ContentTypeHandler(GenericQuoteVerifyCB(config), "application/json")).Methods("GET")
}

func GenericQuoteVerifyCB(config *config.Configuration) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var data QuoteData
		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			return &resourceError{Message: "GenericQuoteVerifyCB - Invalid Input:" + err.Error(),
				StatusCode: http.StatusBadRequest}
		}

		blob := data.QuoteBlob

		obj := parser.ParseSkcQuoteBlob(blob)
		if obj == nil {
			return &resourceError{Message: "GenericQuoteVerifyCB - ParseSkcQuoteBlob parsing failed",
				StatusCode: http.StatusBadRequest}
		}

		if obj.GetQuoteType() == parser.QuoteTypeEcdsa {
			return SGXECDSAQuoteVerifyCB(w, r, obj, config)
		} else if obj.GetQuoteType() == parser.QuoteTypeSw {
			return SwQuoteVerifyCB(w, r, obj, config)
		} else {
			return &resourceError{Message: "GenericQuoteVerifyCB - Quote Type is Invalid",
				StatusCode: http.StatusBadRequest}
		}
		return nil
	}
}

func SwQuoteVerifyCB(w http.ResponseWriter, r *http.Request,
	skcBlobParser *parser.SkcBlobParsed, config *config.Configuration) error {
	rsaBytes, err := skcBlobParser.GetRSAPubKeyObj()
	if err != nil {
		return &resourceError{Message: "GetRSAPubKeyObj: Error: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // HTTP 200

	res := SwResponse{
		Status:                "Success",
		Message:               "Software(SW) Quote Verification Successful",
		ChallengeKeyType:      "RSA",
		SwIssuer:              "Intel",
		ChallengeRsaPublicKey: string(rsaBytes),
	}
	js, err := json.Marshal(res)
	if err != nil {
		return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
	}
	w.Write(js)
	return nil
}

func SGXECDSAQuoteVerifyCB(w http.ResponseWriter, r *http.Request, skcBlobParser *parser.SkcBlobParsed,
	config *config.Configuration) error {
	if len(skcBlobParser.GetQuoteBlob()) == 0 {
		return &resourceError{Message: "Invalid SGX ECDSA Quote", StatusCode: http.StatusBadRequest}
	}

	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParser.GetQuoteBlob())
	if quoteObj == nil {
		return &resourceError{Message: "Invalid SGX ECDSA Quote", StatusCode: http.StatusBadRequest}
	}

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil {
		return &resourceError{Message: "Invalid SGX Quote PCK Cert Data: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	certObj := parser.NewPCKCertObj(pckCertBytes)
	if certObj == nil {
		return &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
		quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCRLObj(), config.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "PCK Certificate Verification failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifyPCKCRL(certObj.GetPckCRLURLs(), certObj.GetPckCRLObj(), certObj.GetPckCRLInterCAList(),
		certObj.GetPckCRLRootCAList(), config.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "Invalid PCK CRL Data: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	tcbObj, err := parser.NewTCBInfo(certObj.GetFMSPCValue())
	if err != nil {
		return &resourceError{Message: "Get TCB Info data parsing/fetch failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	err = VerifyTCBInfo(certObj, tcbObj, config.TrustedRootCA)
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

	_, err = VerifyQeIdentity(qeIdObj, quoteObj, config.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "VerifyQeIdentity failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	rsaBytes, err := skcBlobParser.GetRSAPubKeyObj()
	if err != nil {
		return &resourceError{Message: "GetRSAPubKeyObj: Error: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifiySHA256Hash(quoteObj.GetSHA256Hash(), skcBlobParser.GetPubKeyBlob())
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "VerifiySHA256Hash failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	blob1, err := quoteObj.GetRawBlob1()
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob data in SGX ECDSA Quote: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASignature1(quoteObj.GetECDSASignature1(), blob1, certObj.GetECDSAPublicKey())
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

	_, err = verifier.VerifySGXECDSASignature2(quoteObj.GetECDSASignature2(), blob2, quoteObj.GetECDSAPublicKey2())
	if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "SGX ECDSA Signature Verification(2) failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // HTTP 200

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
	w.Write(js)
	log.Info("Sgx Ecdsa Quote Verification completed:", string(js))
	return nil
}

func VerifyQEIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed) (bool, error) {
	_, err := verifier.VerifyMiscSelect(quoteObj.GetQEReportMiscSelect(), qeIdObj.GetQeIdMiscSelect(),
		qeIdObj.GetQeIdMiscSelectMask())
	if err != nil {
		return false, errors.Wrap(err, "VerifyQEIdentityReport: ")
	}

	_, err = verifier.VerifyAttributes(quoteObj.GetQEReportAttributes(), qeIdObj.GetQeIdAttributes(),
		qeIdObj.GetQeIdAttributesMask())
	if err != nil {
		return false, errors.Wrap(err, "VerifyQEIdentityReport:")
	}

	_, err = verifier.VerifyReportAttributeSize32(quoteObj.GetQEReportMrSigner(), "MrSigner", qeIdObj.GetQeIdMrSigner())
	if err != nil {
		return false, errors.Wrap(err, "VerifyQEIdentityReport")
	}

	if quoteObj.GetQEReportProdId() != qeIdObj.GetQeIdIsvProdId() {
		return false, errors.New("VerifyQEIdentityReport: IsvProdId in quote does not match with PCS QE response")
	}

	/*if quoteObj.GetQEReportIsvSvn() != qeIdObj.GetQeIdIsvSvn() {
		return false, errors.New("VerifyQEIdentityReport: IsvSvn in quote does not match with PCS QE response")
	}*/
	return true, nil
}

func VerifyQeIdentity(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed,
	trustedRootCA *x509.Certificate) (bool, error) {

	if qeIdObj == nil || quoteObj == nil {
		return false, errors.New("VerifyQeIdentity: QEIdentity/Quote Object is empty")
	}
	_, err := verifier.VerifyQEIdentityCertChain(qeIdObj.GetQEInfoInterCAList(), qeIdObj.GetQEInfoRootCAList(),
		trustedRootCA)
	if err != nil {
		return false, errors.Wrap(err, "VerifyQeIdentity: VerifyQEIdentityCertChain")
	}

	status := qeIdObj.GetQeIdentityStatus()
	if status == false {
		return false, errors.New("VerifyQeIdentity: GetQeIdentityStatus is invalid")
	}

	if utils.CheckDate(qeIdObj.GetQeIdIssueDate(), qeIdObj.GetQeIdNextUpdate()) == false {
		return false, errors.New("VerifyQeIdentity: Date Check validation failed")
	}

	return VerifyQEIdentityReport(qeIdObj, quoteObj)
}

func VerifyTCBInfo(certObj *parser.PckCert, tcbObj *parser.TcbInfoStruct, trustedRootCA *x509.Certificate) error {
	if tcbObj.GetTcbInfoFmspc() != certObj.GetFMSPCValue() {
		return errors.New("VerifyTCBInfo: FMSPC in TCBInfoStruct does not match with PCK Cert FMSPC")
	}

	_, err := verifier.VerifyTcbInfoCertChain(tcbObj.GetTCBInfoInterCAList(), tcbObj.GetTCBInfoRootCAList(),
		trustedRootCA)
	if err != nil {
		return errors.Wrap(err, "VerifyTCBInfo: failed to verify Tcbinfo Certchain")
	}

	if utils.CheckDate(tcbObj.GetTcbInfoIssueDate(), tcbObj.GetTcbInfoNextUpdate()) == false {
		return errors.New("VerifyTCBInfo: Date Check validation failed")
	}

	return nil
}
