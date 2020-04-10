/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"os"
	"fmt"
	"time"
	"strings"
	"net/url"
	"net/http"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"
	"github.com/pkg/errors"

	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	commLog "intel/isecl/lib/common/v2/log"
	cos "intel/isecl/lib/common/v2/os"
)

var log = commLog.GetDefaultLogger()

func DumpDataInHex(label string, data []byte, len int) {
	log.Printf("%s[%d]:", label, len)
	dumper := hex.Dumper(os.Stderr)
	defer dumper.Close()
	dumper.Write(data)
}

func GetHTTPClientObj()(*http.Client, *config.Configuration, error) {
	conf := config.Global()
	if conf == nil {
		return nil, nil, errors.New("Configuration pointer is null")
	}

	timeout := time.Duration(5 * time.Second)
	client  := &http.Client{
		Timeout: timeout,
	}

	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCAsStoreDir, "*.pem")
	if err != nil {
		return nil, nil, errors.Wrap(err, "Could not read root CA certificate")
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	for _, rootCACert := range rootCaCertPems{
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return  nil, nil, errors.Wrap(err, "failed to append certs from pem")
		}
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs: rootCAs,
			},
		},
	}
	return client, conf, nil
}

func GetCertPemData(cert *x509.Certificate) ([]byte, error) {
	var err error
	if cert == nil {
		return nil, errors.Wrap(err, "Certificate Object is empty")
	}

	block := &pem.Block{
		Type: "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(block)
	return pemData, nil
}

func GetCertObjListFromStr(certChainStr string) ([]*x509.Certificate, error) {
	certChainEscapedStr, err := url.QueryUnescape(certChainStr)
	if err != nil{
		return nil, errors.Wrap(err, "GetCertObjListFromStr: Error parsing Cert Chain QueryUnescape")
	}

	certCount := strings.Count( certChainEscapedStr, "-----END CERTIFICATE-----")
	if certCount == 0 {
		return nil, errors.Wrap(err, "GetCertObjListFromStr: Invalid Certificate PEM string")
	}

	certs := strings.SplitAfterN( certChainEscapedStr, "-----END CERTIFICATE-----", certCount)
	certChainObjList := make( []*x509.Certificate, certCount)

	for i := 0; i < len(certs); i++ {
		log.Debug("Certificate[", i, "]:", string(certs[i]))
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil{
			return nil, errors.Wrap(err, "GetCertObjListFromStr: Pem Decode error")
		}
		certChainObjList[i], err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "GetCertObjListFromStr: Parse Certificate error")
		}
	}
	log.Debug("GetCertObjListFromStr parsed: ", len(certChainObjList), " certificates from string: ", certChainEscapedStr)
	return certChainObjList, nil
}

func BoolToInt(b bool) (int) {
        n := 0
        if b {
          n = 1
        }
        return n
}

func IntToBool(i int) (bool) {
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
                log.Error("CheckData: IssueDate parse:" +err.Error())
		return false
        }

        nUpdate, err := time.Parse(time.RFC3339, nextUpdate)
        if err != nil {
                log.Error("CheckData: NextUpdate parse:"+err.Error())
		return false
        }

	curTimeAfterIssDate := universalTime.After(iDate)
	curTimeBeforeNextUpdate := universalTime.Before(nUpdate)

	log.Debug("Issuedate:", issueDate, ", nextUpdate:", nextUpdate,
			", Current Date:", universalTime)
        if (curTimeAfterIssDate == false || curTimeBeforeNextUpdate == false) {
                log.Error(fmt.Sprintf("CheckDate: CheckDate Validataion Failed, Time After IssueDate : %v, Time Before NextUpdate : %v",
				curTimeAfterIssDate, curTimeBeforeNextUpdate))
                return false
        } else {
                return true
        }
}
