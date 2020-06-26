/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v2"
	"intel/isecl/lib/clients/v2/aas"
	commLog "intel/isecl/lib/common/v2/log"
	"intel/isecl/sqvs/config"
	"intel/isecl/sqvs/constants"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var log = commLog.GetDefaultLogger()
var statusUpdateLock *sync.Mutex

var (
	c         = config.Global()
	aasClient = aas.NewJWTClient(c.AuthServiceUrl)
	aasRWLock = sync.RWMutex{}
)

func init() {
	aasRWLock.Lock()
	defer aasRWLock.Unlock()
	if aasClient.HTTPClient == nil {
		c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
		if err != nil {
			return
		}
		aasClient.HTTPClient = c
	}
}

func AddJWTToken(req *http.Request) error {
	if aasClient.BaseURL == "" {
		aasClient = aas.NewJWTClient(c.AuthServiceUrl)
		if aasClient.HTTPClient == nil {
			c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
			if err != nil {
				return errors.Wrap(err, "addJWTToken: Error initializing http client")
			}
			aasClient.HTTPClient = c
		}
	}
	aasRWLock.RLock()
	jwtToken, err := aasClient.GetUserToken(c.SQVS.User)
	aasRWLock.RUnlock()
	// something wrong
	if err != nil {
		// lock aas with w lock
		aasRWLock.Lock()
		defer aasRWLock.Unlock()
		// check if other thread fix it already
		jwtToken, err = aasClient.GetUserToken(c.SQVS.User)
		// it is not fixed
		if err != nil {
			aasClient.AddUser(c.SQVS.User, c.SQVS.Password)
			err = aasClient.FetchAllTokens()
			jwtToken, err = aasClient.GetUserToken(c.SQVS.User)
			if err != nil {
				return errors.Wrap(err, "addJWTToken: Could not fetch token")
			}
		}
	}
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

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
		return nil, errors.Wrap(err, "GetCertObjList: Invalid Certificate PEM string")
	}

	certs := strings.SplitAfterN(certChainEscapedStr, "-----END CERTIFICATE-----", certCount)
	certChainObjList := make([]*x509.Certificate, certCount)

	for i := 0; i < len(certs); i++ {
		log.Debug("Certificate[", i, "]:", string(certs[i]))
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

func CheckDate(issueDate string, nextUpdate string) bool {
	universalTime := time.Now().UTC()

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

	curTimeAfterIssDate := universalTime.After(iDate)
	curTimeBeforeNextUpdate := universalTime.Before(nUpdate)

	log.Debug("Issuedate:", issueDate, ", nextUpdate:", nextUpdate,
		", Current Date:", universalTime)
	if curTimeAfterIssDate == false || curTimeBeforeNextUpdate == false {
		log.Error(fmt.Sprintf("CheckDate: CheckDate Validataion Failed, Time After IssueDate : %v, Time Before NextUpdate : %v",
			curTimeAfterIssDate, curTimeBeforeNextUpdate))
		return false
	} else {
		return true
	}
}
