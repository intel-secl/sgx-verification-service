/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"fmt"
	"strings"
	"errors"
	"net/http"
	"crypto/x509"
	"encoding/json"
	"intel/isecl/svs/config"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"


	"intel/isecl/svs/resource/utils"
	"intel/isecl/svs/resource/parser"
	"intel/isecl/svs/resource/verifier"

	log "github.com/sirupsen/logrus"
)
type SwResponse struct{
        Status          	string
        Message         	string
        SwIssuer         	string
	ChallengeKeyType	string
	ChallengeRsaPublicKey	string
}

type SGXResponse struct{
        Status          	string
        Message         	string

	ChallengeKeyType	string
	ChallengeRsaPublicKey	string
	EnclaveIssuer		string
	EnclaveIssuerProdID	string
	EnclaveIssuerExtProdID	string
	EnclaveMeasurement	string
	ConfigSvn		string
	IsvSvn			string	
	ConfigId		string
}
type QuoteData struct {
        QuoteBlob		string  `json:"quote"`
}

func QuoteVerifyCB(router *mux.Router, config *config.Configuration) {
	router.Handle("/verifyQuote", handlers.ContentTypeHandler( GenericQuoteVerifyCB(config), "application/json")).Methods("POST")
	router.Handle("/push", handlers.ContentTypeHandler( GenericQuoteVerifyCB(config), "application/json")).Methods("GET")
}

func GenericQuoteVerifyCB(config *config.Configuration) errorHandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) error {
		var data QuoteData
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			return &resourceError{Message: "GenericQuoteVerifyCB - Invalid Input:"+ err.Error(), 
						StatusCode: http.StatusBadRequest}
		}

		blob := data.QuoteBlob
		log.Debug("GenericQuoteVerifyCB: Blob: ", blob)

		obj := parser.ParseSkcQuoteBlob(blob)
		if obj == nil {
			return &resourceError{Message: "GenericQuoteVerifyCB - ParseSkcQuoteBlob parsing failed", 
					StatusCode: http.StatusBadRequest}
		}
		

		if obj.GetQuoteType() == parser.QuoteTypeEcdsa {
			return SGXECDSAQuoteVerifyCB(w, r, obj, config)
		}else if obj.GetQuoteType() == parser.QuoteTypeSw {
			return SwQuoteVerifyCB(w, r, obj, config)
		}
		return nil
	}
}
func SwQuoteVerifyCB(w http.ResponseWriter, r *http.Request, skcBlobParser *parser.SkcBlobParsed, config *config.Configuration) error { 

	rsaBytes, err := skcBlobParser.GetRSAPubKeyObj()
        if err != nil {
                return &resourceError{Message: "GetRSAPubKeyObj: Error: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }

	w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK) // HTTP 200

        res := SwResponse{ 
			Status			: "Success", 
			Message			: "Software(SW) Quote Verification is Success",
			ChallengeKeyType	: "RSA",
			SwIssuer		: "Intel",
			ChallengeRsaPublicKey	: string(rsaBytes),
	}
        js, err := json.Marshal(res)
        if err != nil {
                return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
        }
        w.Write(js)
        return nil
}
        

func VerifyTCBInfo(quoteObj *parser.SgxQuoteParsed, certObj *parser.PckCert, tcbObj *parser.TcbInfoStruct, trustedRootCA *x509.Certificate)(error){

	if tcbObj.GetTcbInfoFmspc() != certObj.GetFMSPCValue(){
		return errors.New("VerifyTCBInfo: FMSPC not matched with PCK Cert FMSPC")
        }

	_, err := verifier.VerifyTcbInfoCertChain( tcbObj.GetTCBInfoInterCAList(), tcbObj.GetTCBInfoRootCAList(),
			trustedRootCA)
	if err != nil{
		return errors.New("VerifyTCBInfo: "+ err.Error())
	}

	if strings.Compare( tcbObj.GetTcbInfoStatus() , "UpToDate" ) != 0 {
		return errors.New("VerifyTCBInfo: Invalid TcbInfo Stauts:"+ tcbObj.GetTcbInfoStatus())
	}

/*

	pubKey := tcbObj.GetTCBInfoPublicKey()
	if pubKey == nil{
		return errors.New("VerifyTCBInfo: ECDSA Public Key not found")
	}

	data, err := tcbObj.GetTcbInfoSignature()
        if err!=nil {
		return errors.New("VerifyTCBInfo: "+err.Error())
        }
	utils.DumpDataInHex("TCB Info Signature", data, len(data))
	utils.DumpDataInHex("TCB Info Blob", tcbObj.GetTcbInfoBlob(), len(tcbObj.GetTcbInfoBlob()))


	_, err = verifier.VerifySGXECDSASignature1(data, tcbObj.GetTcbInfoBlob(), pubKey)
        if err!=nil {
		return errors.New("VerifyTCBInfo: "+err.Error())
        }
*/
	return nil
}

func SGXECDSAQuoteVerifyCB(w http.ResponseWriter, r *http.Request, skcBlobParser *parser.SkcBlobParsed, config *config.Configuration) error { 
	if len(skcBlobParser.GetQuoteBlob()) == 0 {
		return &resourceError{Message: "Invalid SGX ECDSA Quote", StatusCode: http.StatusBadRequest}
	}
        
	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParser.GetQuoteBlob())
        if quoteObj == nil {
		return &resourceError{Message: "Invalid SGX ECDSA Quote", StatusCode: http.StatusBadRequest}
        }
        quoteObj.DumpSGXQuote()

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil{
		return &resourceError{Message: "Invalid SGX Quote PCK Cert Data: "+ err.Error(),
					 StatusCode: http.StatusBadRequest}
	}
	
        certObj := parser.NewPCKCertObj(pckCertBytes)
        if certObj == nil {
		return &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
        }
	log.Debug("Parsing is completed")

	_, err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
					quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCRLObj(), config.TrustedRootCA)
	if err != nil {
		return &resourceError{Message: "PCK Certificate Verificateion failed: "+err.Error() , 
					StatusCode: http.StatusInternalServerError}
	}	

	_, err = verifier.VerifyPCKCRL(certObj.GetPckCRLURLs(), certObj.GetPckCRLObj(), certObj.GetPckCRLInterCAList(),
					certObj.GetPckCRLRootCAList(), config.TrustedRootCA)
        if err != nil {
		return &resourceError{Message: "Invalid PCK CRL Data: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }

	log.Debug("CRL Verification completed")

        tcbObj, err := parser.NewTCBInfo(certObj.GetFMSPCValue())
	if err != nil {
                return &resourceError{Message: "Get TCB Info data parsing/fetch failed: "+err.Error(), 
						StatusCode: http.StatusInternalServerError }
        }
	//tcbObj.DumpTcbInfo()

	err = VerifyTCBInfo(quoteObj, certObj, tcbObj, config.TrustedRootCA)
        if err != nil {
                return &resourceError{Message: "VerifyTCBInfo verification failed: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }

	qeIdObj, err := parser.NewQeIdentity()
        if err != nil {
                return &resourceError{Message: "QEIdentity Parsing failed: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }
	//qeIdObj.DumpQeIdentity()
	_, err = VerifyQeIdentity(qeIdObj, quoteObj, config.TrustedRootCA)
        if err != nil {
                return &resourceError{Message: "VerifyQeIdentity failed: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }
	rsaBytes, err := skcBlobParser.GetRSAPubKeyObj()
        if err != nil {
                return &resourceError{Message: "GetRSAPubKeyObj: Error: "+err.Error(), 
						StatusCode: http.StatusInternalServerError}
        }

	_, err = verifier.VerifiySHA256Hash(quoteObj.GetSHA256Hash(), skcBlobParser.GetPubKeyBlob())
        if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "VerifiySHA256Hash failed: "+err.Error(), 
					StatusCode: http.StatusInternalServerError}
        }

        blob1, err := quoteObj.GetRawBlob1()
        if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob data in SGX ECDSA Quote: "+err.Error(), 
					StatusCode: http.StatusInternalServerError}
        }

        _, err = verifier.VerifySGXECDSASignature1(quoteObj.GetECDSASignature1(), blob1, certObj.GetECDSAPublicKey())
        if err!=nil {
		return &resourceError{Message: "SGX ECDSA Signature Verification(1) failed: "+err.Error(), 
					StatusCode: http.StatusInternalServerError}
        }
        blob2, err := quoteObj.GetRawBlob2()
        if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob 2 data in SGX ECDSA Quote: "+err.Error(), 
					StatusCode: http.StatusInternalServerError}
        }


        _, err = verifier.VerifySGXECDSASignature2(quoteObj.GetECDSASignature2(), blob2, quoteObj.GetECDSAPublicKey2())
        if err != nil {
		log.Error(err.Error())
		return &resourceError{Message: "SGX ECDSA Signature Verification(2) failed: "+err.Error(),
					 StatusCode: http.StatusInternalServerError}
        }
	w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK) // HTTP 200

        res := SGXResponse{ 
			Status			: "Success", 
			Message			: "SGX ECDSA Quote Verification is Success",
			ChallengeKeyType	: "RSA",
			ChallengeRsaPublicKey	: string(rsaBytes),
			EnclaveIssuer		: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrSigner),
		 	EnclaveIssuerProdID	: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvProdId),
		 	EnclaveIssuerExtProdID	: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvextProdId),
			EnclaveMeasurement	: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.MrEnclave ),
			ConfigSvn		: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxConfigSvn ),
			IsvSvn			: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.SgxIsvSvn ),
			ConfigId		: fmt.Sprintf("%02x", quoteObj.Header.ReportBody.ConfigId ) ,
	}
        js, err := json.Marshal(res)
        if err != nil {
		log.Debug("Invalid PCK CRL Data")
                return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
        }
        w.Write(js)
        return nil
}

func VerifyQEIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed) ( bool, error ) {

        _, err := verifier.VerifyMiscSelect(quoteObj.GetQEReportMiscSelect(), qeIdObj.GetQeIdMiscSelect(), 
						qeIdObj.GetQeIdMiscSelectMask())
	if err!= nil{
                return false, errors.New("VerifyQEIdentityReport: "+ err.Error())
        }

	_, err = verifier.VerifyAttributes(quoteObj.GetQEReportAttributes(), qeIdObj.GetQeIdAttributes(), 
						qeIdObj.GetQeIdAttributesMask())
	if err!= nil{
                return false, errors.New("VerifyQEIdentityReport: "+ err.Error())
        }

        _, err = verifier.VerifyReportAttributeSize32(quoteObj.GetQEReportMrSigner(), "MrSigner", qeIdObj.GetQeIdMrSigner())
	if err != nil{
                return false, errors.New("VerifyQEIdentityReport: "+ err.Error())
        }

        if quoteObj.GetQEReportProdId() != uint16(qeIdObj.GetQeIdIsvProdId()){
                return false, errors.New("VerifyQEIdentityReport: IsvProdId is differed")
        }
        if quoteObj.GetQEReportIsvSvn() != uint16(qeIdObj.GetQeIdIsvSvn()){
                return false, errors.New("VerifyQEIdentityReport: IsvSvn is differed")
        }
	return true, nil
}
func VerifyQeIdentity(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed, trustedRootCA *x509.Certificate) ( bool, error ) {

        if qeIdObj == nil || quoteObj == nil {
                return false, errors.New("VerifyQeIdentity: QEIdentity/Quote Object is empty")
        }
	_, err := verifier.VerifyQEIdentityCertChain(qeIdObj.GetQEInfoInterCAList(), qeIdObj.GetQEInfoRootCAList(),
                        trustedRootCA)
	if err != nil {
                return false, errors.New("VerifyQeIdentity: VerifyQEIdentityCertChain: "+ err.Error())
        }

	status := qeIdObj.GetQeIdentityStatus()
        if status == false {
                return false, errors.New("VerifyQeIdentity: GetQeIdentityStatus is invalid")
        }


        if utils.CheckDate(qeIdObj.GetQeIdIssueDate(), qeIdObj.GetQeIdNextUpdate()) == false {
                return false, errors.New("VerifyQeIdentity: Date Check validation failed")
        }

/*
	pubKey := qeIdObj.GetQEInfoPublicKey()
	if pubKey == nil{
		return false, errors.New("VerifyQeIdentity: ECDSA Public Key not found")
	}
	sign, err :=  qeIdObj.GetQeIdSignature()
        if err!=nil {
		return false, errors.New("VerifyQeIdentity: GetQeIdSignature: "+err.Error())
        }

	_, err = verifier.VerifySGXECDSASignature1(sign, qeIdObj.GetQEInfoBlob(), pubKey)
        if err!=nil {
		return false, errors.New("VerifyQeIdentity: "+err.Error())
        }
*/

        return VerifyQEIdentityReport(qeIdObj, quoteObj)
}

