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

type QeIdentityJSON struct {
	EnclaveIdentity EnclaveIdentityType `json:"enclaveIdentity"`
	Signature       string              `json:"signature"`
}

type QeIdentityData struct {
	QEJson         QeIdentityJSON
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
	ID                      string          `json:"id"`
	Version                 uint16          `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	TcbEvaluationDataNumber uint16          `json:"tcbEvaluationDataNumber"`
	MiscSelect              string          `json:"miscselect"`
	MiscSelectMask          string          `json:"miscselectMask"`
	Attributes              string          `json:"attributes"`
	AttributesMask          string          `json:"attributesMask"`
	MrSigner                string          `json:"mrsigner"`
	IsvProdID               uint16          `json:"isvprodid"`
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

	resp, err := client.Do(req)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing qe identity response")
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
		return nil, errors.Wrap(err, "NewQeIdentity: no qe identity data received")
	}

	obj.RawBlob = make([]byte, len(content))
	copy(obj.RawBlob, content)

	if err := json.Unmarshal(content, &obj.QEJson); err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: cannot unmarshal qeidentity data")
	}

	certChainList, err := utils.GetCertObjList(resp.Header.Get("Sgx-Qe-Identity-Issuer-Chain"))
	if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to get QE Identity CertChain")
	}

	obj.RootCA = make(map[string]*x509.Certificate)
	obj.IntermediateCA = make(map[string]*x509.Certificate)

	var intermediateCACount int
	var rootCACount int
	for i := 0; i < len(certChainList); i++ {
		cert := certChainList[i]
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			rootCACount++
			obj.RootCA[cert.Subject.String()] = cert
		}
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing") {
			intermediateCACount++
			obj.IntermediateCA[cert.Subject.String()] = cert
		}
		log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}

	if intermediateCACount == 0 || rootCACount == 0 {
		return nil, errors.Wrap(err, "NewQeIdentityi: Root CA/Intermediate CA Invalid count")
	}

	return obj, nil
}

func (e *QeIdentityData) GetQeInfoInterCaList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.IntermediateCA))
	var i int
	for _, v := range e.IntermediateCA {
		interMediateCAArr[i] = v
		i++
	}
	log.Debug("GetQeInfoInterCaList:", len(interMediateCAArr))
	return interMediateCAArr
}

func (e *QeIdentityData) GetQeInfoRootCaList() []*x509.Certificate {
	rootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int
	for _, v := range e.RootCA {
		rootCAArr[i] = v
		i++
	}
	log.Debug("GetQeInfoRootCaList:", len(rootCAArr))
	return rootCAArr
}

func (e *QeIdentityData) GetQeIdentityStatus() bool {
	sign, err := e.getQeIDSignature()
	if err != nil {
		return false
	}
	if !utils.IntToBool(int(e.getQeIDVer())) || !utils.IntToBool(len(e.GetQeIDIssueDate())) ||
		!utils.IntToBool(len(e.GetQeIDMiscSelect())) || !utils.IntToBool(len(e.GetQeIDMiscSelectMask())) ||
		!utils.IntToBool(len(e.GetQeIDAttributes())) || !utils.IntToBool(len(e.GetQeIDAttributesMask())) ||
		!utils.IntToBool(len(e.GetQeIDMrSigner())) || !utils.IntToBool(int(e.GetQeIDIsvProdID())) ||
		!utils.IntToBool(int(e.GetQeIDIsvSvn())) || !utils.IntToBool(len(sign)) {
		return false
	}
	return true
}

func (e *QeIdentityData) getQeIDVer() uint16 {
	return e.QEJson.EnclaveIdentity.Version
}

func (e *QeIdentityData) GetQeIDIssueDate() string {
	return e.QEJson.EnclaveIdentity.IssueDate
}

func (e *QeIdentityData) GetQeIDNextUpdate() string {
	return e.QEJson.EnclaveIdentity.NextUpdate
}

func (e *QeIdentityData) GetQeIDMiscSelect() string {
	return e.QEJson.EnclaveIdentity.MiscSelect
}

func (e *QeIdentityData) GetQeIDMiscSelectMask() string {
	return e.QEJson.EnclaveIdentity.MiscSelectMask
}

func (e *QeIdentityData) GetQeIDAttributes() string {
	return e.QEJson.EnclaveIdentity.Attributes
}

func (e *QeIdentityData) GetQeIDAttributesMask() string {
	return e.QEJson.EnclaveIdentity.AttributesMask
}

func (e *QeIdentityData) GetQeIDMrSigner() string {
	return e.QEJson.EnclaveIdentity.MrSigner
}

func (e *QeIdentityData) GetQeIDIsvProdID() uint16 {
	return e.QEJson.EnclaveIdentity.IsvProdID
}

func (e *QeIdentityData) GetQeIDIsvSvn() uint16 {
	for i := 0; i < len(e.QEJson.EnclaveIdentity.TcbLevels); i++ {
		if e.QEJson.EnclaveIdentity.TcbLevels[i].TcbStatus == "UpToDate" {
			return e.QEJson.EnclaveIdentity.TcbLevels[i].Tcb.IsvSvn
		}
	}
	return 0
}

func (e *QeIdentityData) getQeIDSignature() ([]byte, error) {
	data, err := hex.DecodeString(e.QEJson.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "getQeIDSignature: error in decode string")
	}
	return data, nil
}

func (e *QeIdentityData) DumpQeIdentity() {
	log.Debug("===========QEIdentity==============")
	log.Printf("ID: %v", e.QEJson.EnclaveIdentity.ID)
	log.Printf("Version: %v", e.QEJson.EnclaveIdentity.Version)
	log.Printf("IssueDate: %v", e.QEJson.EnclaveIdentity.IssueDate)
	log.Printf("NextUpdate: %v", e.QEJson.EnclaveIdentity.NextUpdate)
	log.Printf("miscselect: %v", e.QEJson.EnclaveIdentity.MiscSelect)
	log.Printf("miscselectMask: %v", e.QEJson.EnclaveIdentity.MiscSelectMask)
	log.Printf("attributes: %v", e.QEJson.EnclaveIdentity.Attributes)
	log.Printf("attributesMask: %v", e.QEJson.EnclaveIdentity.AttributesMask)
	log.Printf("mrsigner: %v", e.QEJson.EnclaveIdentity.MrSigner)
	log.Printf("isvprodid: %v", e.QEJson.EnclaveIdentity.IsvProdID)
	log.Printf("Signature: %v", e.QEJson.Signature)
}
