/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

type TestData struct {
	Description string
	Recorder    *httptest.ResponseRecorder
	Assert      *assert.Assertions
	Router      *mux.Router
	Test        *testing.T
	Token       string
	URL         string
	StatusCode  int
	PostData    []byte
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	sr := r.PathPrefix("/svs/v1/").Subrouter()
	func(setters ...func(*mux.Router)) {
		for _, s := range setters {
			s(sr)
		}
	}(QuoteVerifyCB)
	return r
}
