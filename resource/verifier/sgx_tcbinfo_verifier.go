/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"intel/isecl/sqvs/v3/constants"
	"strings"

	"github.com/pkg/errors"
)

func VerifyTcbInfoCertChain(interCA, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) error {
	numInterCA := len(interCA)
	numRootCA := len(rootCA)

	if numInterCA == 0 || numRootCA == 0 {
		return errors.New("VerifyTcbInfo: InterCA/RootCA is empty")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return errors.New("VerifyTcbInfo: Trusted CA Verification Failed")
	}

	for i := 0; i < numInterCA; i++ {
		err := verifyInterCaCert(interCA[i], rootCA, constants.SGXTCBInfoSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyTcbInfo: verifyInterCaCert failed")
		}
	}
	for i := 0; i < numRootCA; i++ {
		err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyTcbInfo: verifyRootCaCert failed")
		}
	}

	log.Debug("TcbInfo Certificate Chain Verification is Successful")
	return nil
}
