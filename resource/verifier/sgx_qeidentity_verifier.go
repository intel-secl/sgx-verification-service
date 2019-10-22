/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"errors"
	"strings"
	"crypto/x509"
	"encoding/hex"
	"encoding/binary"
	"intel/isecl/svs/constants"

	log "github.com/sirupsen/logrus"
)


func VerifyQEIdentityCertChain( interCA []*x509.Certificate, rootCA []*x509.Certificate, trustedRootCA *x509.Certificate)(bool, error){
	if len(interCA) == 0 || len(rootCA) == 0 {
		return false, errors.New("VerifyQEIdentityCertChain: InterCA/RootCA is empty")
	}

        for i:=0; i<len(interCA);i++ {
                _, err := VerifyInterCACertificate( interCA[i], rootCA, constants.SGXQEInfoSubjectStr)
                if err != nil {
                        return false, errors.New("VerifyQEIdentityCertChain: VerifyInterCACertificate failed: "+ err.Error())
                }
        }
        for i:=0; i<len(rootCA);i++ {
                _, err := VerifyRootCACertificate( rootCA[i], constants.SGXRootCACertSubjectStr)
                if err != nil {
                        return false, errors.New("VerifyQEIdentityCertChain: VerifyRootCACertificate failed: "+ err.Error())
                }
        }

	if strings.Compare( string(trustedRootCA.Signature), string(rootCA[0].Signature)) != 0 {
                return false, errors.New("VerifyQEIdentityCertChain: Trusted CA Verification Failed")
        }
	log.Debug("VerifyQEIdentityCertChainCertChain is succesfull")
	return true, nil
}


func VerifyReportAttributeSize32(QeReportAttribute [32]uint8, attributeName string, attribute string) ( bool, error ) {
        attrArr, err := hex.DecodeString(attribute)
        if  err != nil {
                return false,errors.New("VerifyReportAttributeSize32: "+ attributeName +": hex decode failed:"+err.Error())
        }

	if len(attrArr) != 32 {
                return false,errors.New("VerifyReportAttributeSize32: "+ attributeName +": Invalid Report attribute") 
	}

        attributeInt :=  binary.LittleEndian.Uint32(attrArr)
	log.Printf( "VerifyReportAttributeSize32: %s: ReportAttr: 0x%04x, Attr: 0x%04x", 
				attributeName, QeReportAttribute, attributeInt)

	for i:=0; i<len(attrArr); i++{
		if byte(QeReportAttribute[i]) != attrArr[i] {
                	return false,errors.New("VerifyReportAttributeSize32: "+ attributeName +" validation failed")
		}
		//log.Printf("VerifyReportAttributeSize32: val1:0x%02x, val2:0x%02x", QeReportAttribute[i], attrArr[i])
		
	}
	log.Debug("VerifyReportAttributeSize32: "+  attributeName + ": validation passed")
	return true, nil
}

func VerifyMiscSelect(reportMiscSelect uint32, miscSelect string, miscSelectMask string) ( bool, error ) {
        log.Printf("VerifyTCBInfo: reportMiscSelect: %v, mask: %v, reportMisc:%v", reportMiscSelect, miscSelectMask, miscSelect)
        miscSelectQeArr, err := hex.DecodeString(miscSelect)
        if  err != nil {
                return false,errors.New("VerifyMiscSelect: hex decode failed(1):"+err.Error())
        }
        miscSelectQe :=  binary.LittleEndian.Uint32(miscSelectQeArr)

        miscSelectMaskQeArr, err := hex.DecodeString(miscSelectMask)
        if  err != nil {
                return false, errors.New("VerifyMiscSelect: hex decode failed(1):"+err.Error())
        }
        miscSelectMaskQe :=  binary.LittleEndian.Uint32(miscSelectMaskQeArr)


        log.Printf("VerifyTCBInfo: reportMiscSelect: 0x%04x, reportMiscSelectQe: 0x%04x, reportMiscSelectMaskQe:0x%04x",
                                reportMiscSelect, miscSelectQe, miscSelectMaskQe)
        if (miscSelectMaskQe & reportMiscSelect) == miscSelectQe {
                return true, nil
        }
        return false, errors.New("VerifyMiscSelect: failed")
}

func VerifyAttributes( reportAttribute [2]uint64, QeAttributes string, QeAttributeMask string) ( bool, error ){

	QeAttributeArr, err := hex.DecodeString(QeAttributes)
        if err != nil {
                return false, errors.New("VerifyAttributes: QeAttributeArr: "+err.Error())
        }

	if len(QeAttributeArr) != 16 {
                return false, errors.New("VerifyAttributes: Invalid QeAttribute data")
	}
	
	QeAttributeFlagsInt :=  binary.LittleEndian.Uint64(QeAttributeArr[:8])
	QeAttributeXfrmInt :=  binary.LittleEndian.Uint64(QeAttributeArr[8:])


	QeAttributeMaskArr, err := hex.DecodeString(QeAttributeMask)
        if err != nil {
                return false, errors.New("VerifyAttributes: QeAttributeMaskArr: "+err.Error())
        }

	if len(QeAttributeMaskArr) != 16 {
                return false, errors.New("VerifyAttributes: Invalid QeAttributeMask data")
	}

	QeAttributeMaskFlagsInt :=  binary.LittleEndian.Uint64(QeAttributeMaskArr[:8])
	QeAttributeMaskXfrmInt :=  binary.LittleEndian.Uint64(QeAttributeMaskArr[8:])

	if (( reportAttribute[0] & QeAttributeMaskFlagsInt ) ==  QeAttributeFlagsInt) &&
		(( reportAttribute[1] & QeAttributeMaskXfrmInt ) ==  QeAttributeXfrmInt) {
		return true, nil
	}
        return false, errors.New("VerifyAttributes: failed")
}
