/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	"intel/isecl/sqvs/v3/config"
	"intel/isecl/sqvs/v3/constants"
	"intel/isecl/sqvs/v3/resource/utils"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
)

const (
	Error = iota
	EqualOrGreater
	Lower
	Undefined
)

type TcbType struct {
	SgxTcbComp01Svn uint8  `json:"sgxtcbcomp01svn"`
	SgxTcbComp02Svn uint8  `json:"sgxtcbcomp02svn"`
	SgxTcbComp03Svn uint8  `json:"sgxtcbcomp03svn"`
	SgxTcbComp04Svn uint8  `json:"sgxtcbcomp04svn"`
	SgxTcbComp05Svn uint8  `json:"sgxtcbcomp05svn"`
	SgxTcbComp06Svn uint8  `json:"sgxtcbcomp06svn"`
	SgxTcbComp07Svn uint8  `json:"sgxtcbcomp07svn"`
	SgxTcbComp08Svn uint8  `json:"sgxtcbcomp08svn"`
	SgxTcbComp09Svn uint8  `json:"sgxtcbcomp09svn"`
	SgxTcbComp10Svn uint8  `json:"sgxtcbcomp10svn"`
	SgxTcbComp11Svn uint8  `json:"sgxtcbcomp11svn"`
	SgxTcbComp12Svn uint8  `json:"sgxtcbcomp12svn"`
	SgxTcbComp13Svn uint8  `json:"sgxtcbcomp13svn"`
	SgxTcbComp14Svn uint8  `json:"sgxtcbcomp14svn"`
	SgxTcbComp15Svn uint8  `json:"sgxtcbcomp15svn"`
	SgxTcbComp16Svn uint8  `json:"sgxtcbcomp16svn"`
	PceSvn          uint16 `json:"pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbType `json:"tcb"`
	TcbDate   string  `json:"tcbDate"`
	TcbStatus string  `json:"tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	Fmspc                   string          `json:"fmspc"`
	PceId                   string          `json:"pceId"`
	TcbType                 uint            `json:"tcbType"`
	TcbEvaluationDataNumber uint            `json:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json:"tcbLevels"`
}

type TcbInfoJson struct {
	TcbInfo   TcbInfoType `json:"tcbInfo"`
	Signature string      `json:"signature"`
}

type TcbInfoStruct struct {
	TcbInfoData    TcbInfoJson
	RootCA         map[string]*x509.Certificate
	IntermediateCA map[string]*x509.Certificate
	RawBlob        []byte
}
type ECDSASignature struct {
	R, S *big.Int
}

func NewTcbInfo(fmspc string) (*TcbInfoStruct, error) {
	var err error
	if len(fmspc) < constants.FmspcLen {
		return nil, errors.Wrap(err, "NewTcbInfo: FMSPC value not found")
	}

	tcbInfoStruct := new(TcbInfoStruct)
	err = tcbInfoStruct.getTcbInfoStruct(fmspc)
	if err != nil {
		return nil, errors.Wrap(err, "NewTcbInfo: Failed to get Tcb Info")
	}
	return tcbInfoStruct, nil
}

func (e *TcbInfoStruct) GetTcbInfoInterCaList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.IntermediateCA))
	var i int
	for _, v := range e.IntermediateCA {
		interMediateCAArr[i] = v
		i++
	}
	return interMediateCAArr
}

func (e *TcbInfoStruct) GetTcbInfoRootCaList() []*x509.Certificate {
	rootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int
	for _, v := range e.RootCA {
		rootCAArr[i] = v
		i++
	}
	return rootCAArr
}

func (e *TcbInfoStruct) GetTcbInfoIssueDate() string {
	return e.TcbInfoData.TcbInfo.IssueDate
}

func (e *TcbInfoStruct) GetTcbInfoNextUpdate() string {
	return e.TcbInfoData.TcbInfo.NextUpdate
}

func (e *TcbInfoStruct) getTcbInfoStruct(fmspc string) error {
	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("getTcbInfoStruct: Configuration pointer is null"), "Config error")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return errors.Wrap(err, "getTcbInfoStruct: Error in getting client object")
	}

	url := fmt.Sprintf("%s/tcb", conf.SCSBaseUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("getTcbInfoStruct: req object error")
		return errors.Wrap(err, "getTcbInfoStruct: Failed to Get http NewRequest")
	}

	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	q.Add("fmspc", fmspc)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing tcbinfo response")
			}
		}()
	}

	if err != nil {
		return errors.Wrap(err, "getTcbInfoStruct: Failed to Get tcbinfo response from scs")
	}
	log.Debug("getTcbInfoStruct: Got status:", resp.StatusCode, ", content-len:", resp.ContentLength, " resp body:", resp.Body)

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("getTcbInfoStruct: Invalid Status code received: %d", resp.StatusCode))
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "getTcbInfoStruct: tcbinfo read response failed ")
	}

	if len(content) == 0 {
		return errors.Wrap(err, "getTcbInfoStruct: no tcbinfo data received")
	}

	e.RawBlob = make([]byte, len(content))

	copy(e.RawBlob, content)

	log.Debug("GetTcbInfoJson: blob[", resp.ContentLength, "]:", len(e.RawBlob))

	certChainList, err := utils.GetCertObjList(resp.Header.Get("SGX-TCB-Info-Issuer-Chain"))
	if err != nil {
		return errors.Wrap(err, "getTcbInfoStruct: failed to get cert object")
	}

	if err := json.Unmarshal(content, &e.TcbInfoData); err != nil {
		return errors.Wrap(err, "getTcbInfoStruct: TcbInfo Unmarshal Failed")
	}

	e.RootCA = make(map[string]*x509.Certificate)
	e.IntermediateCA = make(map[string]*x509.Certificate)

	var intermediateCACount int
	var rootCACount int
	for i := 0; i < len(certChainList); i++ {
		cert := certChainList[i]
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			rootCACount++
			e.RootCA[cert.Subject.String()] = cert
		}
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing") {
			intermediateCACount++
			e.IntermediateCA[cert.Subject.String()] = cert
		}
		log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}
	if intermediateCACount == 0 || rootCACount == 0 {
		return errors.Wrap(err, "getTcbInfoStruct: intermediate CA or Root CA is empty")
	}
	return nil
}

func (e *TcbInfoStruct) GetTcbInfoFmspc() string {
	return e.TcbInfoData.TcbInfo.Fmspc
}

func compareTcbComponents(pckComponents []byte, pckpcesvn uint16, tcbComponents []byte, tcbpcesvn uint16) int {
	leftLower := false
	rightLower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		leftLower = true
	}
	if pckpcesvn > tcbpcesvn {
		rightLower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			leftLower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			rightLower = true
		}
	}
	// this should not happen as either one can be greater
	if leftLower && rightLower {
		return Undefined
	}
	if leftLower {
		return Lower
	}
	return EqualOrGreater
}

func getTcbCompList(tcbLevelList *TcbType) []byte {
	tcbCompLevel := make([]byte, constants.MaxTcbLevels)

	tcbCompLevel[0] = tcbLevelList.SgxTcbComp01Svn
	tcbCompLevel[1] = tcbLevelList.SgxTcbComp02Svn
	tcbCompLevel[2] = tcbLevelList.SgxTcbComp03Svn
	tcbCompLevel[3] = tcbLevelList.SgxTcbComp04Svn
	tcbCompLevel[4] = tcbLevelList.SgxTcbComp05Svn
	tcbCompLevel[5] = tcbLevelList.SgxTcbComp06Svn
	tcbCompLevel[6] = tcbLevelList.SgxTcbComp07Svn
	tcbCompLevel[7] = tcbLevelList.SgxTcbComp08Svn
	tcbCompLevel[8] = tcbLevelList.SgxTcbComp09Svn
	tcbCompLevel[9] = tcbLevelList.SgxTcbComp10Svn
	tcbCompLevel[10] = tcbLevelList.SgxTcbComp11Svn
	tcbCompLevel[11] = tcbLevelList.SgxTcbComp12Svn
	tcbCompLevel[12] = tcbLevelList.SgxTcbComp13Svn
	tcbCompLevel[13] = tcbLevelList.SgxTcbComp14Svn
	tcbCompLevel[14] = tcbLevelList.SgxTcbComp15Svn
	tcbCompLevel[15] = tcbLevelList.SgxTcbComp16Svn

	return tcbCompLevel
}

func (e *TcbInfoStruct) GetTcbUptoDateStatus(tcbLevels []byte) string {
	pckComponents := tcbLevels[:16]
	pckPceSvn := binary.LittleEndian.Uint16(tcbLevels[16:])

	var status string
	var tcbComponents []byte
	// iterate through all TCB Levels present in TCBInfo
	for i := 0; i < len(e.TcbInfoData.TcbInfo.TcbLevels); i++ {
		tcbPceSvn := e.TcbInfoData.TcbInfo.TcbLevels[i].Tcb.PceSvn
		tcbComponents = getTcbCompList(&e.TcbInfoData.TcbInfo.TcbLevels[i].Tcb)
		tcbError := compareTcbComponents(pckComponents, pckPceSvn, tcbComponents, tcbPceSvn)
		if tcbError == EqualOrGreater {
			status = e.TcbInfoData.TcbInfo.TcbLevels[i].TcbStatus
			break
		}
	}
	return status
}

func (e *TcbInfoStruct) DumpTcbInfo() {
	log.Printf("Version:         %v", e.TcbInfoData.TcbInfo.Version)
	log.Printf("IssueDate:       %v", e.TcbInfoData.TcbInfo.IssueDate)
	log.Printf("NextUpdate:      %v", e.TcbInfoData.TcbInfo.NextUpdate)
	log.Printf("Fmspc:           %v", e.TcbInfoData.TcbInfo.Fmspc)
	log.Printf("pceId:           %v", e.TcbInfoData.TcbInfo.PceId)
	log.Printf("Sgxtcbcomp01svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp01Svn)
	log.Printf("Sgxtcbcomp02svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp02Svn)
	log.Printf("Sgxtcbcomp03svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp03Svn)
	log.Printf("Sgxtcbcomp04svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp04Svn)
	log.Printf("Sgxtcbcomp05svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp05Svn)
	log.Printf("Sgxtcbcomp06svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp06Svn)
	log.Printf("Sgxtcbcomp07svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp07Svn)
	log.Printf("Sgxtcbcomp08svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp08Svn)
	log.Printf("Sgxtcbcomp09svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp09Svn)
	log.Printf("Sgxtcbcomp10svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp10Svn)
	log.Printf("Sgxtcbcomp11svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp11Svn)
	log.Printf("Sgxtcbcomp12svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp12Svn)
	log.Printf("Sgxtcbcomp13svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp13Svn)
	log.Printf("Sgxtcbcomp14svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp14Svn)
	log.Printf("Sgxtcbcomp15svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp15Svn)
	log.Printf("Sgxtcbcomp16svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.SgxTcbComp16Svn)
	log.Printf("Status:          %v", e.TcbInfoData.TcbInfo.TcbLevels[0].TcbStatus)
	log.Printf("Pcesvn:          %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.PceSvn)
	log.Printf("Signature:       %v", e.TcbInfoData.Signature)
}
