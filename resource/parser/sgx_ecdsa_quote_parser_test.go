/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"bytes"
	"testing"
	"net/http"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
)

type TestData struct {
	Description string
	Recorder *httptest.ResponseRecorder
	Assert   *assert.Assertions
	Test     *testing.T
	Token    string
	Url      string
	StatusCode int
	PostData []byte
}

func ExecuteSGXQuoteTest(input TestData){
	input.Test.Log("Test:", input.Description)
	if len(input.PostData)> 0 {
	httptest.NewRequest("POST", input.Url, bytes.NewReader(input.PostData))
	}else {
		httptest.NewRequest("POST", input.Url, nil)
	}
}

func TestGetSgxQuote(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Test:t,
			Url : "/svs/sgx/test/platforminfo/push",
			StatusCode: http.StatusBadRequest,
			PostData : nil,
			Token:"invalidtoken",
		Description: "Without Query Params",
	}
	ExecuteSGXQuoteTest(input)
}
