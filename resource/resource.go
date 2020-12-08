/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/lib/common/v3/auth"
	"intel/isecl/lib/common/v3/context"
	"intel/isecl/sqvs/v3/constants"
	"net/http"

	clog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	ct "intel/isecl/lib/common/v3/types/aas"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := ehf(w, r); err != nil {
		slog.WithError(err).Error("HTTP Error")
		switch t := err.(type) {
		case *resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func AuthorizeEndpoint(r *http.Request, roleName string, retNilCtxForEmptyCtx bool) error {
	log.Trace("resource/resource:AuthorizeEndpoint() Entering")
	defer log.Trace("resource/resource:AuthorizeEndpoint() Leaving")

	privileges, err := context.GetUserRoles(r)
	if err != nil {
		slog.WithError(err).Error("resource/resource: AuthorizeEndpoint() Failed to read roles and permissions")
		return &resourceError{Message: "Could not get user roles from http context", StatusCode: http.StatusInternalServerError}
	}

	_, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges, []ct.RoleInfo{{Service: constants.ServiceName, Name: roleName}}, retNilCtxForEmptyCtx)
	if !foundRole {
		slog.Infof("resource/resource: AuthorizeEndpoint() %s: endpoint access unauthorized, request role: %v", commLogMsg.UnauthorizedAccess, roleName)
		return &privilegeError{Message: "", StatusCode: http.StatusForbidden}
	}
	slog.Infof("resource/resource: AuthorizeEndpoint() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
	return nil
}
