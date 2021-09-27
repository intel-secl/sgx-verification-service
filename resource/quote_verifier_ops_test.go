/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		Router:      setupRouter(),
		Test:        t,
		URL:         "/svs/v1",
		StatusCode:  http.StatusBadRequest,
		PostData:    nil,
		Token:       "invalidtoken",
		Description: "Without Query Params",
	}
	ExecuteSGXQuoteTest(input)
}

func TestSgxQuotePushInvalidData(t *testing.T) {
	input := TestData{
		Recorder:    httptest.NewRecorder(),
		Assert:      assert.New(t),
		Router:      setupRouter(),
		Test:        t,
		URL:         "/svs/v1/test/push",
		Token:       "invalidtoken",
		StatusCode:  http.StatusUnauthorized,
		PostData:    nil,
		Description: "InvalidToken",
	}
	//input.Assert.Equal(input.StatusCode, input.Recorder.Code)
	input.Test.Log("Test:", input.Description, ", Response:", input.Recorder.Body)
	input.Test.Log("Test:", input.Description, " ended")
	ExecuteSGXQuoteTest(input)
}

func TestSgxQuotePushInvalidJson(t *testing.T) {
	input := TestData{
		Recorder:    httptest.NewRecorder(),
		Assert:      assert.New(t),
		Router:      setupRouter(),
		Test:        t,
		URL:         "/svs/v1/test-noauth/push",
		Token:       "",
		StatusCode:  http.StatusUnauthorized,
		PostData:    nil,
		Description: "InvalidToken",
	}

	sgxAgentPostBody := map[string]interface{}{
		"enc_ppid": "invalidppid",
	}
	input.PostData, _ = json.Marshal(sgxAgentPostBody)
	input.StatusCode = http.StatusBadRequest
	ExecuteSGXQuoteTest(input)

}
