/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"intel/isecl/svs/constants"
	"strings"
)

func VerifyTcbInfoCertChain(interCA []*x509.Certificate, rootCA []*x509.Certificate,
	trustedRootCA *x509.Certificate) (bool, error) {
	if len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyTcbInfo: InterCA/RootCA is empty")
	}

	for i := 0; i < len(interCA); i++ {
		_, err := VerifyInterCACertificate(interCA[i], rootCA, constants.SGXTCBInfoSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyTcbInfo: VerifyInterCACertificate failed")
		}
	}
	for i := 0; i < len(rootCA); i++ {
		_, err := VerifyRootCACertificate(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyTcbInfo: VerifyRootCACertificate failed")
		}
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyTcbInfo: Trusted CA Verification Failed")
	}
	log.Debug("VerifyTcbInfoCertChain is succesfull")
	return true, nil
}
