/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
)

func testServerHTTP(statusCode int) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		switch statusCode {
		case 500:
			w.WriteHeader(http.StatusInternalServerError)
			return &resourceError{Message: "InternalServerError", StatusCode: http.StatusInternalServerError}
		case 501:
			w.WriteHeader(http.StatusNotImplemented)
			return resourceError{Message: "StatusNotImplemented", StatusCode: http.StatusNotImplemented}
		case 401:
			w.WriteHeader(http.StatusUnauthorized)
			return &privilegeError{Message: "StatusUnauthorized", StatusCode: http.StatusUnauthorized}
		case 403:
			w.WriteHeader(http.StatusForbidden)
			return privilegeError{Message: "Forbidden", StatusCode: http.StatusForbidden}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			return errors.New("default error")
		}
	}
}

func TestErrorHandlerFuncServeHTTP(t *testing.T) {
	var w http.ResponseWriter
	var r *http.Request

	w = httptest.NewRecorder()

	ts := testServerHTTP(http.StatusInternalServerError)
	ts.ServeHTTP(w, r)

	ts = testServerHTTP(http.StatusNotImplemented)
	ts.ServeHTTP(w, r)

	ts = testServerHTTP(http.StatusUnauthorized)
	ts.ServeHTTP(w, r)

	ts = testServerHTTP(http.StatusForbidden)
	ts.ServeHTTP(w, r)

	ts = testServerHTTP(http.StatusNotFound)
	ts.ServeHTTP(w, r)
}
