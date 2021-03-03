/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	"net/url"
	"strings"
	"time"
)

var log = commLog.GetDefaultLogger()

func GetCertPemData(cert *x509.Certificate) ([]byte, error) {
	var err error
	if cert == nil {
		return nil, errors.Wrap(err, "Certificate Object is empty")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(block)
	return pemData, nil
}

func GetCertObjList(certChainStr string) ([]*x509.Certificate, error) {
	certChainEscapedStr, err := url.QueryUnescape(certChainStr)
	if err != nil {
		return nil, errors.Wrap(err, "GetCertObjList: Error parsing Cert Chain QueryUnescape")
	}

	certCount := strings.Count(certChainEscapedStr, "-----END CERTIFICATE-----")
	if certCount == 0 {
		return nil, errors.Wrap(err, "GetCertObjList: no certificates were found")
	}

	certs := strings.SplitAfterN(certChainEscapedStr, "-----END CERTIFICATE-----", certCount)
	certChainObjList := make([]*x509.Certificate, certCount)

	for i := 0; i < len(certs); i++ {
		log.Debug("Certificate[", i, "]:", certs[i])
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil {
			return nil, errors.Wrap(err, "GetCertObjList: Pem Decode error")
		}
		certChainObjList[i], err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "GetCertObjList: Parse Certificate error")
		}
	}
	log.Debug("GetCertObjList parsed: ", len(certChainObjList), " certificates from string: ", certChainEscapedStr)
	return certChainObjList, nil
}

func IntToBool(i int) bool {
	if i != 0 {
		return true
	} else {
		return false
	}
}

func CheckDate(issueDate, nextUpdate string) bool {
	iDate, err := time.Parse(time.RFC3339, issueDate)
	if err != nil {
		log.Error("CheckData: IssueDate parse:" + err.Error())
		return false
	}

	nUpdate, err := time.Parse(time.RFC3339, nextUpdate)
	if err != nil {
		log.Error("CheckData: NextUpdate parse:" + err.Error())
		return false
	}

	universalTime := time.Now().UTC()

	curTimeAfterIssDate := universalTime.After(iDate)
	curTimeBeforeNextUpdate := universalTime.Before(nUpdate)

	if !curTimeAfterIssDate || !curTimeBeforeNextUpdate {
		log.Error(fmt.Sprintf("CheckDate: CheckDate Validataion Failed, Time After IssueDate : %v, Time Before NextUpdate : %v",
			curTimeAfterIssDate, curTimeBeforeNextUpdate))
		return false
	} else {
		return true
	}
}
