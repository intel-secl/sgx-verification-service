/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

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

type SGXResponse struct {
	ReportData        string `json:"reportData,omitempty"`
	UserDataHashMatch string `json:"userDataMatch,omitempty"`
	AdditionalQuoteData
}

type AdditionalQuoteData struct {
	Message             string
	EnclaveIssuer       string `json:"EnclaveIssuer,omitempty"`
	EnclaveMeasurement  string `json:"EnclaveMeasurement,omitempty"`
	EnclaveIssuerProdID string `json:"EnclaveIssuerProdID,omitempty"`
	IsvSvn              string `json:"IsvSvn,omitempty"`
	TcbLevel            string `json:"TcbLevel,omitempty"`
	Quote               string `json:"Quote,omitempty"`
	Challenge           string `json:"Challenge,omitempty"`
}
