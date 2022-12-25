/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CredentialsController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	BeforeEach(func() {
		router = mux.NewRouter()
	})

	Describe("SetVersionRoutes", func() {
		Context("Get Version request", func() {
			It("Should return Version - Valid getVersion request", func() {
				SetVersionRoutes(router)
				req, err := http.NewRequest(http.MethodGet, "/version", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})
})
