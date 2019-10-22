/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import ( 

        "testing"
	"github.com/gorilla/mux"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
	"intel/isecl/svs/config"
)


type TestData struct {
	Description string
	Recorder *httptest.ResponseRecorder
	Assert   *assert.Assertions
	Router   *mux.Router
	Test     *testing.T
	Token 	 string
	Url	 string
        StatusCode int
	PostData []byte
}

func mockRetrieveJWTSigningCerts() error{
	return nil
}

func setupRouter(t *testing.T) *mux.Router {

        r := mux.NewRouter()
        sr := r.PathPrefix("/svs/v1/").Subrouter()
	func(setters ...func(*mux.Router, *config.Configuration)) {
                for _, s := range setters {
                        s(sr, nil)
                }
        }(QuoteVerifyCB)
        return r
}
