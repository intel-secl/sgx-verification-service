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

func VerifyQeIdCertChain(interCA []*x509.Certificate, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate) (bool, error) {
	if len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyQeIdCertChain: InterCA/RootCA is empty")
	}

	for i := 0; i < len(interCA); i++ {
		_, err := verifyInterCaCert(interCA[i], rootCA, constants.SGXQEInfoSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyQeIdCertChain: verifyInterCaCert failed")
		}
	}
	for i := 0; i < len(rootCA); i++ {
		_, err := verifyRootCaCert(rootCA[i], constants.SGXRootCACertSubjectStr)
		if err != nil {
			return false, errors.Wrap(err, "VerifyQeIdCertChain: verifyRootCaCert failed")
		}
	}

	if strings.Compare(string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
		return false, errors.New("VerifyQeIdCertChain: Trusted CA Verification Failed")
	}
	log.Debug("Verify QEIdentity CertChain is succesfull")
	return true, nil
}

func VerifyReportAttrSize(QeReportAttribute [32]uint8, attributeName string, attribute string) (bool, error) {
	attrArr, err := hex.DecodeString(attribute)
	if err != nil {
		return false, errors.Wrap(err, "VerifyReportAttrSize: "+attributeName+": hex decode failed:")
	}

	if len(attrArr) != 32 {
		return false, errors.New("VerifyReportAttrSize: " + attributeName + ": Invalid Report attribute")
	}

	for i := 0; i < len(attrArr); i++ {
		if byte(QeReportAttribute[i]) != attrArr[i] {
			return false, errors.New("VerifyReportAttrSize: " + attributeName + " validation failed")
		}
	}
	log.Debug("VerifyReportAttrSize: " + attributeName + ": validation passed")
	return true, nil
}

func VerifyMiscSelect(reportMiscSelect uint32, miscSelect string, miscSelectMask string) (bool, error) {
	miscSelectQeArr, err := hex.DecodeString(miscSelect)

	if err != nil {
		return false, errors.Wrap(err, "VerifyMiscSelect: hex decode failed(1)")
	}
	miscSelectQe := binary.LittleEndian.Uint32(miscSelectQeArr)

	miscSelectMaskQeArr, err := hex.DecodeString(miscSelectMask)
	if err != nil {
		return false, errors.Wrap(err, "VerifyMiscSelect: hex decode failed(1)")
	}
	miscSelectMaskQe := binary.LittleEndian.Uint32(miscSelectMaskQeArr)

	if (miscSelectMaskQe & reportMiscSelect) == miscSelectQe {
		return true, nil
	}
	return false, errors.New("VerifyMiscSelect: failed")
}

func VerifyAttributes(reportAttribute [2]uint64, QeAttributes string, QeAttributeMask string) (bool, error) {
	QeAttributeArr, err := hex.DecodeString(QeAttributes)
	if err != nil {
		return false, errors.Wrap(err, "VerifyAttributes: QeAttributeArr")
	}

	if len(QeAttributeArr) != 16 {
		return false, errors.New("VerifyAttributes: Invalid QeAttribute data")
	}

	QeAttributeFlagsInt := binary.LittleEndian.Uint64(QeAttributeArr[:8])
	QeAttributeXfrmInt := binary.LittleEndian.Uint64(QeAttributeArr[8:])

	QeAttributeMaskArr, err := hex.DecodeString(QeAttributeMask)
	if err != nil {
		return false, errors.Wrap(err, "VerifyAttributes: QeAttributeMaskArr")
	}

	if len(QeAttributeMaskArr) != 16 {
		return false, errors.New("VerifyAttributes: Invalid QeAttributeMask data")
	}

	QeAttributeMaskFlagsInt := binary.LittleEndian.Uint64(QeAttributeMaskArr[:8])
	QeAttributeMaskXfrmInt := binary.LittleEndian.Uint64(QeAttributeMaskArr[8:])

	if ((reportAttribute[0] & QeAttributeMaskFlagsInt) == QeAttributeFlagsInt) &&
		((reportAttribute[1] & QeAttributeMaskXfrmInt) == QeAttributeXfrmInt) {
		return true, nil
	}
	return false, errors.New("VerifyAttributes: failed")
}
