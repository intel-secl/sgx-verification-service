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
	"strconv"
	"net/url"
	"net/http"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"

	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/log"
	cos "intel/isecl/lib/common/os"
)

var log = commLog.GetDefaultLogger()

func DumpDataInHex( label string, data []byte, len int){
	log.Trace("resource/utils/utils:DumpDataInHex() Entering")
	defer log.Trace("resource/utils/utils:DumpDataInHex() Leaving")

	log.Printf("%s[%d]:", label, len)
	dumper := hex.Dumper(os.Stderr)
	defer dumper.Close()
	dumper.Write(data)
}

func GetHTTPClientObj()(*http.Client, *config.Configuration, error){
	log.Trace("resource/utils/utils:GetHTTPClientObj() Entering")
	defer log.Trace("resource/utils/utils:GetHTTPClientObj() Leaving")
	
	var err error
	conf:= config.Global()
	if conf == nil {
		return nil, nil, errors.Wrap(err, "Configuration pointer is null")
	}

	timeout := time.Duration(5 * time.Second)
	client  := &http.Client{
		Timeout: timeout,
	}

	proxy, _ := strconv.ParseBool(conf.ProxyEnable)
	if len(conf.ProxyUrl) > 0 && proxy {
		log.Debug("ProxyUrl: ",conf.ProxyUrl)
		proxyUrl, err := url.Parse(conf.ProxyUrl)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to get proxy url")
		}
		client.Transport = &http.Transport{ Proxy: http.ProxyURL(proxyUrl)}
		log.WithField("Proxy URL", conf.ProxyUrl).Debug("Intel Prov Client OPS")
	} else {
		rootCaCertPems, err := cos.GetDirFileContents(constants.RootCADirPath, "*.pem" )
		if err != nil {
			return  nil, nil, errors.Wrap(err, "failed to get file contents")
		}

		// Get the SystemCertPool, continue with an empty pool on error
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		for _, rootCACert := range rootCaCertPems{
			if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
				return  nil, nil, errors.Wrap(err, "failed to append certs from pem")
			}
		}

		log.Debug("SCSBaseUrl: ",conf.SCSBaseUrl)
		_, err = url.Parse(conf.SCSBaseUrl)
		if err != nil {
			return nil, nil, errors.Wrap(err,"failed to get caching service url")
		}
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					RootCAs: rootCAs,
				},
			},
		}
		log.WithField("SCS URL", conf.SCSBaseUrl).Debug("SCS prov Client")
	}
	return client, conf, nil
}

func GetCertPemData( obj *x509.Certificate ) ( []byte, error ){
	log.Trace("resource/utils/utils:GetCertPemData() Entering")
	defer log.Trace("resource/utils/utils:GetCertPemData() Leaving")

	var err error
	if obj == nil {
		return nil, errors.Wrap(err, "Certificate Object is empty")
	}

	block := &pem.Block{
		Type: "CERTIFICATE",
		Bytes: obj.Raw,
	}

	pemData := pem.EncodeToMemory(block) 
	return pemData, nil
}

func GetCertObjListFromStr( certChainStr string ) ( []*x509.Certificate, error ){
	log.Trace("resource/utils/utils:GetCertObjListFromStr() Entering")
	defer log.Trace("resource/utils/utils:GetCertObjListFromStr() Leaving")

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

	for i:=0; i<len(certs); i++ {

		log.Debug("Certificate[", i, "]:", string(certs[i]))
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil{
			return nil, errors.Wrap(err, "GetCertObjListFromStr: Pem Decode error")
		}	
		certChainObjList[i], err = x509.ParseCertificate( block.Bytes )
		if err != nil {
			return nil, errors.Wrap(err, "GetCertObjListFromStr: Parse Certificate error")
		}
	}
	log.Debug("GetCertObjListFromStr parsed: ", len(certChainObjList), " certificates from string: ", certChainEscapedStr)
	return certChainObjList, nil
}

func BoolToInt(b bool) (int) {
	log.Trace("resource/utils/utils:BoolToInt() Entering")
	defer log.Trace("resource/utils/utils:BoolToInt() Leaving")

        n := 0
        if b {
          n = 1
        }
        return n
}

func IntToBool(i int) (bool) {
	log.Trace("resource/utils/utils:IntToBool() Entering")
	defer log.Trace("resource/utils/utils:IntToBool() Leaving")

        if i != 0 {
          return true
        } else {
           return false
        }
}

func CheckDate(issueDate string, nextUpdate string) bool {
	log.Trace("resource/utils/utils:CheckDate() Entering")
	defer log.Trace("resource/utils/utils:CheckDate() Leaving")

        universalTime := time.Now().UTC()

        iDate, err := time.Parse(time.RFC3339, issueDate)
        if err!=nil {
                log.Error("CheckData: IssueDate parse:" +err.Error())
		return false
        }

        nUpdate, err := time.Parse(time.RFC3339, nextUpdate)
        if err!=nil {
                log.Error("CheckData: NextUpdate parse:"+err.Error())
		return false
        }

	cond1 := universalTime.Before(iDate)
	cond2 := universalTime.After(nUpdate)

	
	log.Debug("CheckDate: issuedate:", issueDate, ", nextUpdate:", nextUpdate, ", Current Date:", universalTime)
        if cond1 || cond2 {
                log.Error(fmt.Sprintf("CheckData: Validataion Failed, conditon1:%v, condition:%v", 
						cond1,
						cond2))
                return false
        }else {
                return true
        }
}

