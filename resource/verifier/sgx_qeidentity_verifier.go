/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"github.com/pkg/errors"
	"intel/isecl/sqvs/v3/constants"
	"strings"
)

func VerifyQeIDCertChain(interCA, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) (bool, error) {
	if len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyQeIDCertChain: InterCA/RootCA is empty")
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyQeIDCertChain: Trusted CA Verification Failed")
	}

	for i := 0; i < len(interCA); i++ {
		_, err := verifyInterCaCert(interCA[i], rootCA, constants.SGXQEInfoSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyQeIDCertChain: verifyInterCaCert failed")
		}
	}
	for i := 0; i < len(rootCA); i++ {
		_, err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyQeIDCertChain: verifyRootCaCert failed")
		}
	}

	log.Debug("Verify QEIdentity CertChain is succesfull")
	return true, nil
}

func VerifyReportAttrSize(qeReportAttribute [32]uint8, attributeName, attribute string) (bool, error) {
	attrArr, err := hex.DecodeString(attribute)
	if err != nil {
		return false, errors.Wrap(err, "VerifyReportAttrSize: "+attributeName+": hex decode failed:")
	}

	if len(attrArr) != 32 {
		return false, errors.New("VerifyReportAttrSize: " + attributeName + ": Invalid Report attribute")
	}

	for i := 0; i < len(attrArr); i++ {
		if byte(qeReportAttribute[i]) != attrArr[i] {
			return false, errors.New("VerifyReportAttrSize: " + attributeName + " validation failed")
		}
	}
	log.Debug("VerifyReportAttrSize: " + attributeName + ": validation passed")
	return true, nil
}

func VerifyMiscSelect(reportMiscSelect uint32, miscSelect, miscSelectMask string) (bool, error) {
	miscSelectQeArr, err := hex.DecodeString(miscSelect)

	if err != nil {
		return false, errors.Wrap(err, "VerifyMiscSelect: miscSelect hex decode failed")
	}
	miscSelectQe := binary.LittleEndian.Uint32(miscSelectQeArr)

	miscSelectMaskQeArr, err := hex.DecodeString(miscSelectMask)
	if err != nil {
		return false, errors.Wrap(err, "VerifyMiscSelect: miscSelectMask hex decode failed")
	}
	miscSelectMaskQe := binary.LittleEndian.Uint32(miscSelectMaskQeArr)

	if (miscSelectMaskQe & reportMiscSelect) == miscSelectQe {
		return true, nil
	}
	return false, errors.New("VerifyMiscSelect: failed")
}

func VerifyAttributes(reportAttribute [2]uint64, qeAttributes, qeAttributeMask string) (bool, error) {
	qeAttributeArr, err := hex.DecodeString(qeAttributes)
	if err != nil {
		return false, errors.Wrap(err, "VerifyAttributes: qeAttributeArr")
	}

	if len(qeAttributeArr) != 16 {
		return false, errors.New("VerifyAttributes: Invalid QeAttribute data")
	}

	qeAttributeFlags := binary.LittleEndian.Uint64(qeAttributeArr[:8])
	qeAttributeXfrm := binary.LittleEndian.Uint64(qeAttributeArr[8:])

	qeAttributeMaskArr, err := hex.DecodeString(qeAttributeMask)
	if err != nil {
		return false, errors.Wrap(err, "VerifyAttributes: qeAttributeMaskArr")
	}

	if len(qeAttributeMaskArr) != 16 {
		return false, errors.New("VerifyAttributes: Invalid qeAttributeMask data")
	}

	qeAttributeMaskFlags := binary.LittleEndian.Uint64(qeAttributeMaskArr[:8])
	QeAttributeMaskXfrmInt := binary.LittleEndian.Uint64(qeAttributeMaskArr[8:])

	if ((reportAttribute[0] & qeAttributeMaskFlags) == qeAttributeFlags) &&
		((reportAttribute[1] & QeAttributeMaskXfrmInt) == qeAttributeXfrm) {
		return true, nil
	}
	return false, errors.New("VerifyAttributes: failed")
}
