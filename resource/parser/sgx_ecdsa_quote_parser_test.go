/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestData struct {
	Description string
	Recorder    *httptest.ResponseRecorder
	Assert      *assert.Assertions
	Test        *testing.T
	Token       string
	URL         string
	StatusCode  int
	PostData    []byte
}

func ExecuteSGXQuoteTest(input TestData) {
	input.Test.Log("Test:", input.Description)
	if len(input.PostData) > 0 {
		httptest.NewRequest("POST", input.URL, bytes.NewReader(input.PostData))
	} else {
		httptest.NewRequest("POST", input.URL, nil)
	}
}

func TestGetSgxQuote(t *testing.T) {
	input := TestData{
		Recorder:    httptest.NewRecorder(),
		Assert:      assert.New(t),
		Test:        t,
		URL:         "/svs/sgx/test/platforminfo/push",
		StatusCode:  http.StatusBadRequest,
		PostData:    nil,
		Token:       "invalidtoken",
		Description: "Without Query Params",
	}
	ExecuteSGXQuoteTest(input)
}
