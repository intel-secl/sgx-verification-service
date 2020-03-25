/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
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

func ExecuteQPLTest(input TestData){
	input.Test.Log("Test:", input.Description)
	var req *http.Request
	req = httptest.NewRequest("GET", input.Url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

}

func TestGetFmspc(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Test:t,
			Url : "/svs/v1/test/tcb",
			StatusCode: http.StatusBadRequest,
			PostData : nil,
			Token:"",
			Description: "Without Query Params",
	}
	ExecuteQPLTest(input)
	input.Url = "/svs/v1/tcb?fmspc=invalid"
	input.Description = "Invalid Query Params"
	input.Test.Log("Test:", input.Description, " ended")
}
