/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"fmt"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/resource/domain"
	"intel/isecl/sqvs/v5/resource/domain/models"
	"net/http"
)

type FakeSgxEcdsaQuoteVerifier struct {
	StatusCode int
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func NewFakeSGXEcdsaQuoteVerifier(statusCode int) domain.SGXQuoteVerifier {

	return &FakeSgxEcdsaQuoteVerifier{
		StatusCode: statusCode,
	}
}

func (fseqv *FakeSgxEcdsaQuoteVerifier) SgxEcdsaQuoteVerify(data models.QuoteDataWithChallenge, scsClient domain.HttpClient, config *config.Configuration,
	trustedSGXRootCAFile string) (models.SGXResponse, error) {

	if trustedSGXRootCAFile == "" {
		return models.SGXResponse{}, &resourceError{Message: "Empty trustedSGXRootCAFile given", StatusCode: http.StatusBadRequest}
	}

	if fseqv.StatusCode == 400 {
		return models.SGXResponse{}, &resourceError{Message: "Bad Request", StatusCode: http.StatusBadRequest}
	}

	var resp models.SGXResponse
	resp.Message = "SGX_QL_QV_RESULT_OK"

	resp.UserDataHashMatch = "false"
	resp.ReportData = "0000000000000000000000000000000000000000000000000000000000000000"
	resp.EnclaveIssuer = "d412a4f07ef83892a5915fb2ab584be31e186e5a4f95ab5f6950fd4eb8694d7b"
	resp.EnclaveIssuerProdID = "00"
	resp.EnclaveMeasurement = "9270442d1bd1961fa39dbe1f2cdf4f87950a54fcaf9a2e5013875c3346542dca"
	resp.IsvSvn = "01"
	resp.TcbLevel = "OutofDate"

	return resp, nil
}
