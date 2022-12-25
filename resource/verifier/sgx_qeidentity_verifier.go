/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"intel/isecl/sqvs/v5/constants"
	"strings"

	"github.com/pkg/errors"
)

const (
	AttributeSize = 16
	HashSize      = 32
)

func VerifyQeIDCertChain(interCA, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) error {
	numInterCA := len(interCA)
	numRootCA := len(rootCA)

	if numInterCA == 0 || numRootCA == 0 {
		return errors.New("VerifyQeIDCertChain: InterCA/RootCA is empty")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return errors.New("VerifyQeIDCertChain: Trusted CA Verification Failed")
	}

	for i := 0; i < numInterCA; i++ {
		err := verifyInterCaCert(interCA[i], rootCA, constants.SGXQEInfoSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyQeIDCertChain: verifyInterCaCert failed")
		}
	}
	for i := 0; i < numRootCA; i++ {
		err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return errors.Wrap(err, "VerifyQeIDCertChain: verifyRootCaCert failed")
		}
	}

	log.Debug("Verify QEIdentity CertChain is successful")
	return nil
}

func VerifyReportAttrSize(qeReportAttribute [HashSize]byte, attributeName, attribute string) error {
	attrArr, err := hex.DecodeString(attribute)
	if err != nil {
		return errors.Wrap(err, "VerifyReportAttrSize: "+attributeName+": Cannot Hex Decode Attributes:")
	}

	if bytes.Equal(qeReportAttribute[:], attrArr) {
		log.Debug("VerifyReportAttrSize: " + attributeName + ": Validation Passed")
	} else {
		log.Debug("VerifyReportAttrSize: " + attributeName + ": Validation Failed")
	}
	return nil
}

func VerifyMiscSelect(reportMiscSelect uint32, miscSelect, miscSelectMask string) error {
	miscSelectQeArr, err := hex.DecodeString(miscSelect)

	if err != nil {
		return errors.Wrap(err, "VerifyMiscSelect: miscSelect hex decode failed")
	}
	miscSelectQe := binary.LittleEndian.Uint32(miscSelectQeArr)

	miscSelectMaskQeArr, err := hex.DecodeString(miscSelectMask)
	if err != nil {
		return errors.Wrap(err, "VerifyMiscSelect: miscSelectMask hex decode failed")
	}
	miscSelectMaskQe := binary.LittleEndian.Uint32(miscSelectMaskQeArr)

	if (miscSelectMaskQe & reportMiscSelect) == miscSelectQe {
		return nil
	}
	return errors.New("VerifyMiscSelect: failed")
}

func VerifyAttributes(reportAttribute [AttributeSize]byte, qeAttributes, qeAttributeMask string) error {
	qeAttribute, err := hex.DecodeString(qeAttributes)
	if err != nil {
		return errors.Wrap(err, "VerifyAttributes: qeAttribute")
	}

	qeAttMask, err := hex.DecodeString(qeAttributeMask)
	if err != nil {
		return errors.Wrap(err, "VerifyAttributes: qeAttMask")
	}

	reportAtt := make([]byte, AttributeSize)
	for i := 0; i < AttributeSize; i++ {
		reportAtt[i] = reportAttribute[i] & qeAttMask[i]
	}
	if bytes.Equal(reportAtt, qeAttribute) {
		return nil
	} else {
		return errors.New("VerifyAttributes: failed")
	}
}
