/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	"intel/isecl/sqvs/v3/config"
	"intel/isecl/sqvs/v3/constants"
	"intel/isecl/sqvs/v3/resource/utils"
	"io/ioutil"
	"net/http"
	"strings"
)

type QeIdentityJson struct {
	EnclaveIdentity EnclaveIdentityType `json:"enclaveIdentity"`
	Signature       string              `json:"signature"`
}

type QeIdentityData struct {
	QEJson         QeIdentityJson
	RootCA         map[string]*x509.Certificate
	IntermediateCA map[string]*x509.Certificate
	RawBlob        []byte
}

type TcbInfo struct {
	IsvSvn uint16 `json:"isvsvn"`
}

type TcbLevelsInfo struct {
	Tcb       TcbInfo `json:"tcb"`
	TcbDate   string  `json:"tcbDate"`
	TcbStatus string  `json:"tcbStatus"`
}

type EnclaveIdentityType struct {
	Id                      string          `json:"id"`
	Version                 uint16          `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	TcbEvaluationDataNumber uint16          `json:"tcbEvaluationDataNumber"`
	MiscSelect              string          `json:"miscselect"`
	MiscSelectMask          string          `json:"miscselectMask"`
	Attributes              string          `json:"attributes"`
	AttributesMask          string          `json:"attributesMask"`
	MrSigner                string          `json:"mrsigner"`
	IsvProdId               uint16          `json:"isvprodid"`
	TcbLevels               []TcbLevelsInfo `json:"tcbLevels"`
}

func NewQeIdentity() (*QeIdentityData, error) {
	obj := new(QeIdentityData)

	conf := config.Global()
	if conf == nil {
		return nil, errors.Wrap(errors.New("NewQeIdentity: Configuration pointer is null"), "Config error")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: Error in getting client object")
	}

	url := fmt.Sprintf("%s/qe/identity", conf.SCSBaseUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to get new request")
	}

	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()

	err = utils.AddJWTToken(req)
	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to add JWT token")
	}

	resp, err := client.Do(req)
	if resp != nil {
		defer func() {
			err = resp.Body.Close()
			if err != nil {
				log.WithError(err).Error("Error closing response")
			}
		}()
	}

	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to do client request")
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("NewQeIdentity: Invalid Status code received: %d", resp.StatusCode))
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read Response failed ")
	}

	if len(content) == 0 {
		return nil, errors.Wrap(err, "NewQeIdentity: buffer lenght is zero")
	}

	obj.RawBlob = make([]byte, len(content))
	copy(obj.RawBlob, content)

	if err := json.Unmarshal(content, &obj.QEJson); err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: QeIdentity Unmarshal Failed")
	}

	certChainList, err := utils.GetCertObjList(string(resp.Header.Get("Sgx-Qe-Identity-Issuer-Chain")))
	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to get QE Identity CertChain")
	}

	obj.RootCA = make(map[string]*x509.Certificate)
	obj.IntermediateCA = make(map[string]*x509.Certificate)

	var IntermediateCACount int = 0
	var RootCACount int = 0
	for i := 0; i < len(certChainList); i++ {
		cert := certChainList[i]
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			RootCACount += 1
			obj.RootCA[cert.Subject.String()] = cert
		}
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing") {
			IntermediateCACount += 1
			obj.IntermediateCA[cert.Subject.String()] = cert
		}
		log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}

	if IntermediateCACount == 0 || RootCACount == 0 {
		return nil, errors.Wrap(err, "NewQeIdentityi: Root CA/Intermediate CA Invalid count")
	}

	return obj, nil
}

func (e *QeIdentityData) GetQeInfoInterCaList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.IntermediateCA))
	var i int = 0
	for _, v := range e.IntermediateCA {
		interMediateCAArr[i] = v
		i += 1
	}
	log.Debug("GetQeInfoInterCaList:", len(interMediateCAArr))
	return interMediateCAArr
}

func (e *QeIdentityData) GetQeInfoRootCaList() []*x509.Certificate {
	RootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int = 0
	for _, v := range e.RootCA {
		RootCAArr[i] = v
		i += 1
	}
	log.Debug("GetQeInfoRootCaList:", len(RootCAArr))
	return RootCAArr
}

func (e *QeIdentityData) GetQeIdentityStatus() bool {
	sign, err := e.getQeIdSignature()
	if err != nil {
		return false
	}
	if !utils.IntToBool(int(e.getQeIdVer())) || !utils.IntToBool(len(e.GetQeIdIssueDate())) ||
		!utils.IntToBool(len(e.GetQeIdMiscSelect())) || !utils.IntToBool(len(e.GetQeIdMiscSelectMask())) ||
		!utils.IntToBool(len(e.GetQeIdAttributes())) || !utils.IntToBool(len(e.GetQeIdAttributesMask())) ||
		!utils.IntToBool(len(e.GetQeIdMrSigner())) || !utils.IntToBool(int(e.GetQeIdIsvProdId())) ||
		!utils.IntToBool(int(e.GetQeIdIsvSvn())) || !utils.IntToBool(len(sign)) {
		return false
	}
	return true
}

func (e *QeIdentityData) getQeIdVer() uint16 {
	return e.QEJson.EnclaveIdentity.Version
}

func (e *QeIdentityData) GetQeIdIssueDate() string {
	return e.QEJson.EnclaveIdentity.IssueDate
}

func (e *QeIdentityData) GetQeIdNextUpdate() string {
	return e.QEJson.EnclaveIdentity.NextUpdate
}

func (e *QeIdentityData) GetQeIdMiscSelect() string {
	return e.QEJson.EnclaveIdentity.MiscSelect
}

func (e *QeIdentityData) GetQeIdMiscSelectMask() string {
	return e.QEJson.EnclaveIdentity.MiscSelectMask
}

func (e *QeIdentityData) GetQeIdAttributes() string {
	return e.QEJson.EnclaveIdentity.Attributes
}

func (e *QeIdentityData) GetQeIdAttributesMask() string {
	return e.QEJson.EnclaveIdentity.AttributesMask
}

func (e *QeIdentityData) GetQeIdMrSigner() string {
	return e.QEJson.EnclaveIdentity.MrSigner
}

func (e *QeIdentityData) GetQeIdIsvProdId() uint16 {
	return e.QEJson.EnclaveIdentity.IsvProdId
}

func (e *QeIdentityData) GetQeIdIsvSvn() uint16 {
	for i := 0; i < len(e.QEJson.EnclaveIdentity.TcbLevels); i++ {
		if e.QEJson.EnclaveIdentity.TcbLevels[i].TcbStatus == "UpToDate" {
			return e.QEJson.EnclaveIdentity.TcbLevels[i].Tcb.IsvSvn
		}
	}
	return 0
}

func (e *QeIdentityData) getQeIdSignature() ([]byte, error) {
	data, err := hex.DecodeString(e.QEJson.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "getQeIdSignature: error in decode string")
	}
	return data, nil
}

func (e *QeIdentityData) DumpQeIdentity() {
	log.Debug("===========QEIdentity==============")
	log.Printf("Id: %v", e.QEJson.EnclaveIdentity.Id)
	log.Printf("Version: %v", e.QEJson.EnclaveIdentity.Version)
	log.Printf("IssueDate: %v", e.QEJson.EnclaveIdentity.IssueDate)
	log.Printf("NextUpdate: %v", e.QEJson.EnclaveIdentity.NextUpdate)
	log.Printf("miscselect: %v", e.QEJson.EnclaveIdentity.MiscSelect)
	log.Printf("miscselectMask: %v", e.QEJson.EnclaveIdentity.MiscSelectMask)
	log.Printf("attributes: %v", e.QEJson.EnclaveIdentity.Attributes)
	log.Printf("attributesMask: %v", e.QEJson.EnclaveIdentity.AttributesMask)
	log.Printf("mrsigner: %v", e.QEJson.EnclaveIdentity.MrSigner)
	log.Printf("isvprodid: %v", e.QEJson.EnclaveIdentity.IsvProdId)
	log.Printf("Signature: %v", e.QEJson.Signature)
}
