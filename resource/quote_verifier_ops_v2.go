/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/base64"
	"encoding/json"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/sqvs/v3/config"
	"intel/isecl/sqvs/v3/constants"
	"intel/isecl/sqvs/v3/resource/utils"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func QuoteVerifyCBAndSign(router *mux.Router) {
	router.Handle("/sgx_qv_verify_quote", handlers.ContentTypeHandler(sgxVerifyQuoteAndSign(), "application/json")).Methods("POST")
}

func sgxVerifyQuoteAndSign() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/quote_verifier_ops:sgxVerifyQuoteAndSign() Entering")
		defer log.Trace("resource/quote_verifier_ops:sgxVerifyQuoteAndSign() Leaving")

		conf := config.Global()
		if conf == nil {
			return &resourceError{Message: "Could not read config", StatusCode: http.StatusInternalServerError}
		}
		if conf.IncludeToken {
			err := AuthorizeEndpoint(r, constants.QuoteVerifierGroupName, true)
			if err != nil {
				slog.WithError(err).Error("resource/quote_verifier_ops: sgxVerifyQuoteAndSign() Authorization Error")
				return err
			}
		}

		var data QuoteDataWithChallenge
		if r.ContentLength == 0 {
			slog.Error("resource/quote_verifier_ops: sgxVerifyQuoteAndSign() The request body was not provided")
			return &resourceError{Message: "SGX_QL_ERROR_INVALID_PARAMETER", StatusCode: http.StatusBadRequest}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&data)
		if err != nil {
			slog.WithError(err).Errorf("resource/quote_verifier_ops: sgxVerifyQuoteAndSign() %s:Failed to decode "+
				"request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: "Invalid JSON input provided", StatusCode: http.StatusBadRequest}
		}

		sgxResponse, err := SgxEcdsaQuoteVerify(data)

		var quoteResponseBytes []byte
		if strings.TrimSpace(data.Challenge) != "" && conf.SignQuoteResponse {
			if err != nil {
				sgxResponse.Message = err.Error()
			}
			log.Info("SgxEcdsaQuoteVerify: Signing the quote response")
			sgxResponse.Quote = data.QuoteBlob
			sgxResponse.Challenge = data.Challenge

			dataBytes, err := json.Marshal(QuoteInfo(sgxResponse))
			if err != nil {
				return &resourceError{Message: "Failed to marshal hostPlatformData to get trustReport" +
					err.Error(), StatusCode: http.StatusInternalServerError}
			}

			signature, err := utils.GenerateSignature([]byte(base64.StdEncoding.EncodeToString(dataBytes)), constants.PrivateKeyLocation, conf.UsePSSPadding)
			if err != nil {
				return &resourceError{Message: "Failed to get signature for QVL response: " + err.Error(),
					StatusCode: http.StatusInternalServerError}
			}

			certChain, err := ioutil.ReadFile(constants.PublicKeyLocation)
			if err != nil {
				log.WithError(err).Error("Error reading signing public key from file")
				return &resourceError{Message: "Error reading signing public key from file",
					StatusCode: http.StatusInternalServerError}
			}

			quoteResponseBytes, err = json.Marshal(SignedSGXResponse{
				QuoteData:        base64.StdEncoding.EncodeToString(dataBytes),
				Signature:        signature,
				CertificateChain: string(certChain),
			})
			if err != nil {
				log.WithError(err).Error("Error marshalling signed SGX response in JSON")
				return &resourceError{Message: "Error marshalling signed SGX response in JSON", StatusCode: http.StatusInternalServerError}
			}
		} else {
			if err != nil {
				return err
			}
			quoteResponseBytes, err = json.Marshal(UnsignedSGXResponse{
				QuoteData: QuoteInfo(sgxResponse),
			})
			if err != nil {
				log.WithError(err).Error("Error marshalling SGX response in JSON")
				return &resourceError{Message: "Error marshalling SGX response in JSON", StatusCode: http.StatusInternalServerError}
			}
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
