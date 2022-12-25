/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"intel/isecl/lib/clients/v5"
	clog "intel/isecl/lib/common/v5/log"
)

var log = clog.GetDefaultLogger()

func NewSCSClient(trustedCAsStoreDir string) HttpClient {
	log.Trace("domain/scs_client.go:NewSCSClient() Entering")
	defer log.Trace("resource/scs_client.go:NewSCSClient() Leaving")

	client, err := clients.HTTPClientWithCADir(trustedCAsStoreDir)
	if err != nil {
		log.Errorf("domain/scs_client.go:NewSCSClient() Error in getting client object %v", err)
		return nil
	}
	return client
}
