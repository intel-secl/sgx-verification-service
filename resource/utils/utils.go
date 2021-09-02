/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	commLog "intel/isecl/lib/common/v3/log"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
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

func GenerateSignature(responseBytes []byte, keyFilePath string) (string, error) {
	log.Trace("resource/utils:GenerateSignature() Entering")
	defer log.Trace("resource/utils:GenerateSignature() Leaving")

	var privateKey *rsa.PrivateKey

	//Get the private key from path
	priv, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.WithError(err).Info("error reading signing private key from file")
		return "", errors.Wrap(err, "error reading signing private key from file")
	}

	privPem, _ := pem.Decode(priv)
	parsedKey, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		log.WithError(err).Info("Cannot parse RSA private key from file")
		return "", errors.New("Cannot parse RSA private key from file")
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Error("Unable to parse RSA private key")
		return "", errors.New("Unable to parse RSA private key")
	}

	hash := sha512.Sum384(responseBytes)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		log.WithError(err).Info("Error signing quote response")
		return "", errors.Wrap(err, "Error signing quote response")
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
