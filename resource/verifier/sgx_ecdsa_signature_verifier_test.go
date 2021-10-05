/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
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

func ExecuteQPLTest(input TestData) {
	input.Test.Log("Test:", input.Description)
	req := httptest.NewRequest("GET", input.URL, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
}

func TestGetFmspc(t *testing.T) {
	input := TestData{
		Recorder:    httptest.NewRecorder(),
		Assert:      assert.New(t),
		Test:        t,
		URL:         "/svs/v1/test/tcb",
		StatusCode:  http.StatusBadRequest,
		PostData:    nil,
		Token:       "",
		Description: "Without Query Params",
	}
	ExecuteQPLTest(input)
	input.URL = "/svs/v1/tcb?fmspc=invalid"
	input.Description = "Invalid Query Params"
	input.Test.Log("Test:", input.Description, " ended")
}
