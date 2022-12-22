/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/resource/domain/mocks"
	"intel/isecl/sqvs/v5/test/utils"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	trustedSGXRootCA      = "../../test/trustedSGXRootCA.pem"
	intermediateSGXRootCA = "../../test/intermediateSGXRootCA.pem"
)

func ReadCertFromFile(t *testing.T, certFilePath string) *x509.Certificate {
	_, err := os.Stat(certFilePath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "cert file path does not exist")
	}

	trustedSGXRootCABytes, err := ioutil.ReadFile(certFilePath)
	assert.Nil(t, err)

	pemBlock, _ := pem.Decode(trustedSGXRootCABytes)
	assert.NotNil(t, pemBlock)

	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	assert.Nil(t, err)

	return x509Cert
}

var testQEData = []byte(`{
	"enclaveIdentity": {
		"id": "QE",
		"version": 2,
		"issueDate": "2022-06-15T06:42:01Z",
		"nextUpdate": "2022-07-15T06:42:01Z",
		"tcbEvaluationDataNumber": 5,
		"miscselect": "00000000",
		"miscselectMask": "FFFFFFFF",
		"attributes": "00000000000000000000000000000000",
		"attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
		"mrsigner": "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF",
		"isvprodid": 1,
		"tcbLevels": [{
				"tcb": {
					"isvsvn": 2
				},
				"tcbDate": "2021-05-15T00:00:00Z",
				"tcbStatus": "UpToDate"
			},
			{
				"tcb": {
					"isvsvn": 1
				},
				"tcbDate": "2020-08-15T00:00:00Z",
				"tcbStatus": "OutOfDate"
			}
		]
	},
	"signature": "2c50f0f4297781594e4d86c864ef1bd6797ab77566c9ddc417330ca7f37456f2f998a44e8230c57c2c8f51258ce5044cf0ac0af58e5c953e466f51981dc1390c"
}
`)

func getTestQeIdentityJSON(t *testing.T) QeIdentityJSON {

	var qeIDJSON QeIdentityJSON

	err := json.Unmarshal(testQEData, &qeIDJSON)
	assert.Nil(t, err)
	return qeIDJSON
}

func TestQeIdentityData_GetQeInfoInterCaList(t *testing.T) {

	qeData := &QeIdentityData{}

	qeInfoInterCaList := qeData.GetQeInfoInterCaList()
	assert.NotNil(t, qeInfoInterCaList)

	qeInfoRootCaList := qeData.GetQeInfoRootCaList()
	assert.NotNil(t, qeInfoRootCaList)

	qeIdentityStatus := qeData.GetQeIdentityStatus()
	assert.NotNil(t, qeIdentityStatus)

	qeIDVer := qeData.getQeIDVer()
	assert.NotNil(t, qeIDVer)

	qeIDIssueDate := qeData.GetQeIDIssueDate()
	assert.NotNil(t, qeIDIssueDate)

	qeIDNextUpdate := qeData.GetQeIDNextUpdate()
	assert.NotNil(t, qeIDNextUpdate)

	qeIDMiscSelect := qeData.GetQeIDMiscSelect()
	assert.NotNil(t, qeIDMiscSelect)

	qeIDMiscSelectMask := qeData.GetQeIDMiscSelectMask()
	assert.NotNil(t, qeIDMiscSelectMask)

	qeIDAttributes := qeData.GetQeIDAttributes()
	assert.NotNil(t, qeIDAttributes)

	qeIDAttributesMask := qeData.GetQeIDAttributesMask()
	assert.NotNil(t, qeIDAttributesMask)

	qeIDMrSigner := qeData.GetQeIDMrSigner()
	assert.NotNil(t, qeIDMrSigner)

	qeIDIsvProdID := qeData.GetQeIDIsvProdID()
	assert.NotNil(t, qeIDIsvProdID)

	qeIDIsvSvn := qeData.GetQeIDIsvSvn()
	assert.NotNil(t, qeIDIsvSvn)

	qeIDSignature, err := qeData.getQeIDSignature()
	assert.NotNil(t, qeIDSignature)

	qeData.DumpQeIDentity()

	// few more tests.

	keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Errorf("Failed to create keypair")
	}

	utils.CreateTestCertificate(trustedSGXRootCA, "Intel SGX Root CA", keypair, true, nil)
	utils.CreateTestCertificate(intermediateSGXRootCA, "Intel SGX PCK Processor CA", keypair, true, nil)
	defer func() {
		os.Remove(trustedSGXRootCA)
		os.Remove(intermediateSGXRootCA)
	}()
	rootCert := ReadCertFromFile(t, trustedSGXRootCA)
	intermediateCert := ReadCertFromFile(t, intermediateSGXRootCA)

	rootCAMap := make(map[string]*x509.Certificate)
	interCAMap := make(map[string]*x509.Certificate)

	rootCAMap["root-ca"] = rootCert
	interCAMap["inter-ca"] = intermediateCert

	qedata := &QeIdentityData{
		QEJson:         getTestQeIdentityJSON(t),
		RootCA:         rootCAMap,
		IntermediateCA: interCAMap,
	}

	qeInfoInterCaList = qedata.GetQeInfoInterCaList()
	assert.NotNil(t, qeInfoInterCaList)

	qeInfoRootCaList = qedata.GetQeInfoRootCaList()
	assert.NotNil(t, qeInfoRootCaList)
}

func TestNewQeIdentity(t *testing.T) {

	scsClient := mocks.NewClientMock(http.StatusOK)
	testConfig := config.Load(testConfigFilePath)

	_, err := NewQeIdentity(testConfig, scsClient)
	assert.Nil(t, err)

	// test with negative clients
	scsClient = mocks.NewClientMock(400)
	_, err = NewQeIdentity(testConfig, scsClient)
	assert.NotNil(t, err)

	scsClient = mocks.NewClientMock(401)
	_, err = NewQeIdentity(testConfig, scsClient)
	assert.NotNil(t, err)

	scsClient = mocks.NewClientMock(204)
	_, err = NewQeIdentity(testConfig, scsClient)
	assert.Nil(t, err)

	scsClient = mocks.NewClientMock(202)
	_, err = NewQeIdentity(testConfig, scsClient)
	assert.NotNil(t, err)
}
