/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"intel/isecl/sqvs/v4/version"
	"net/http"

	"github.com/gorilla/mux"
)

func SetVersionRoutes(router *mux.Router) {
	router.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")

	return func(w http.ResponseWriter, r *http.Request) {
		verStr := version.GetVersion()
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(verStr))
		if err != nil {
			log.WithError(err).Error("Could not write version to response")
		}
	}
}
