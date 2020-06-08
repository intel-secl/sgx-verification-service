/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v2"
	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	"intel/isecl/svs/resource/utils"
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
	SgxTcbComp01Svn uint   `json: "sgxtcbcomp01svn"`
	SgxTcbComp02Svn uint   `json: "sgxtcbcomp02svn"`
	SgxTcbComp03Svn uint   `json: "sgxtcbcomp03svn"`
	SgxTcbComp04Svn uint   `json: "sgxtcbcomp04svn"`
	SgxTcbComp05Svn uint   `json: "sgxtcbcomp05svn"`
	SgxTcbComp06Svn uint   `json: "sgxtcbcomp06svn"`
	SgxTcbComp07Svn uint   `json: "sgxtcbcomp07svn"`
	SgxTcbComp08Svn uint   `json: "sgxtcbcomp08svn"`
	SgxTcbComp09Svn uint   `json: "sgxtcbcomp09svn"`
	SgxTcbComp10Svn uint   `json: "sgxtcbcomp10svn"`
	SgxTcbComp11Svn uint   `json: "sgxtcbcomp11svn"`
	SgxTcbComp12Svn uint   `json: "sgxtcbcomp12svn"`
	SgxTcbComp13Svn uint   `json: "sgxtcbcomp13svn"`
	SgxTcbComp14Svn uint   `json: "sgxtcbcomp14svn"`
	SgxTcbComp15Svn uint   `json: "sgxtcbcomp15svn"`
	SgxTcbComp16Svn uint   `json: "sgxtcbcomp16svn"`
	PceSvn          uint16 `json: "pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbType `json: "tcb"`
	TcbDate   string  `json: "tcbDate"`
	TcbStatus string  `json: "tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json: "version"`
	IssueDate               string          `json: "issueDate"`
	NextUpdate              string          `json: "nextUpdate"`
	Fmspc                   string          `json: "fmspc"`
	PceId                   string          `json: "pceId"`
	TcbType                 uint            `json: "tcbType"`
	TcbEvaluationDataNumber uint            `json: "tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json: "tcbLevels"`
}

type TcbInfoJson struct {
	TcbInfo   TcbInfoType `json: "tcbInfo"`
	Signature string      `json: "signature"`
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

func NewTCBInfo(fmspc string) (*TcbInfoStruct, error) {
	var err error
	if len(fmspc) < 0 {
		return nil, errors.Wrap(err, "NewTCBInfo: FMSPC value not found")
	}

	tcbInfoStruct := new(TcbInfoStruct)
	err = tcbInfoStruct.GetTcbInfoStruct(fmspc)
	if err != nil {
		return nil, errors.Wrap(err, "NewTCBInfo: Failed to get Tcb Info")
	}
	return tcbInfoStruct, nil
}

func (e *TcbInfoStruct) GetTCBInfoInterCAList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.IntermediateCA))
	var i int = 0
	for _, v := range e.IntermediateCA {
		interMediateCAArr[i] = v
		i += 1
	}
	return interMediateCAArr
}

func (e *TcbInfoStruct) GetTCBInfoRootCAList() []*x509.Certificate {
	RootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int = 0
	for _, v := range e.RootCA {
		RootCAArr[i] = v
		i += 1
	}
	log.Debug("GetTCBInfoRootCAList:", len(RootCAArr))
	return RootCAArr
}

func (e *TcbInfoStruct) GetTCBInfoPublicKey() *ecdsa.PublicKey {
	for _, v := range e.IntermediateCA {
		if strings.Compare(v.Subject.String(), constants.SGXTCBInfoSubjectStr) == 0 {
			return v.PublicKey.(*ecdsa.PublicKey)
		}
		//utils.DumpDataInHex("Signature:", v.Signature, len(v.Signature))
	}
	log.Error("GetTCBInfoPublicKey: Public Key not found")
	return nil
}

func (e *TcbInfoStruct) GetTcbInfoIssueDate() string {
	return e.TcbInfoData.TcbInfo.IssueDate
}

func (e *TcbInfoStruct) GetTcbInfoNextUpdate() string {
	return e.TcbInfoData.TcbInfo.NextUpdate
}

func (e *TcbInfoStruct) GetTcbInfoStruct(fmspc string) error {
	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("GetTcbInfoStruct: Configuration pointer is null"), "Config error")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return errors.Wrap(err, "GetTcbInfoStruct: Error in getting client object")
	}

	url := fmt.Sprintf("%s/tcb", conf.SCSBaseUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("GetTcbInfoStruct: req object error")
		return errors.Wrap(err, "GetTcbInfoStruct: Failed to Get http NewRequest")
	}

	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	q.Add("fmspc", fmspc)
	req.URL.RawQuery = q.Encode()

	err = utils.AddJWTToken(req)
	if err != nil {
		return errors.Wrap(err, "GetTcbInfoStruct: failed to add JWT token")
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "GetTcbInfoStruct: Failed to Get http client")
	}
	log.Debug("GetTcbInfoStruct: Got status:", resp.StatusCode, ", content-len:", resp.ContentLength, " resp body:", resp.Body)

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("GetTcbInfoJson: Invalid Status code received: %d", resp.StatusCode))
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read Response failed ")
	}
	resp.Body.Close()

	e.RawBlob = make([]byte, len(content))

	copy(e.RawBlob, content)

	log.Debug("GetTcbInfoJson: blob[", resp.ContentLength, "]:", len(e.RawBlob))

	certChainList, err := utils.GetCertObjListFromStr(string(resp.Header.Get("SGX-TCB-Info-Issuer-Chain")))
	if err != nil {
		return errors.Wrap(err, "GetTcbInfoStruct: failed to get object")
	}

	if err := json.Unmarshal(content, &e.TcbInfoData); err != nil {
		return errors.Wrap(err, "TCBInfo Unmarshal Failed")
	}

	e.RootCA = make(map[string]*x509.Certificate)
	e.IntermediateCA = make(map[string]*x509.Certificate)

	var IntermediateCACount int = 0
	var RootCACount int = 0
	for i := 0; i < len(certChainList); i++ {
		cert := certChainList[i]
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			RootCACount += 1
			e.RootCA[cert.Subject.String()] = cert
		}
		if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing") {
			IntermediateCACount += 1
			e.IntermediateCA[cert.Subject.String()] = cert
		}
		log.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}
	if IntermediateCACount == 0 || RootCACount == 0 {
		return errors.Wrap(err, "TCB INFO - Root CA/Intermediate CA Invalid count")
	}

	return nil
}

func (e *TcbInfoStruct) GetTcbInfoFmspc() string {
	return e.TcbInfoData.TcbInfo.Fmspc
}

func (e *TcbInfoStruct) GetTcbInfoBlob() []byte {
	bytes, err := json.Marshal(e.TcbInfoData.TcbInfo)
	if err != nil {
		log.Error("GetTcbInfoBlob: Error in Json Marshalling")
	}
	return bytes
}

func (e *TcbInfoStruct) GetTcbInfoSignature() ([]byte, error) {
	signatureBytes, err := hex.DecodeString(e.TcbInfoData.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "GetTcbInfoSignature: error in decode string")
	}

	rBytes, sBytes := signatureBytes[:32], signatureBytes[32:]
	bytes, err := asn1.Marshal(ECDSASignature{R: new(big.Int).SetBytes(rBytes), S: new(big.Int).SetBytes(sBytes)})
	if err != nil {
		return nil, errors.Wrap(err, "GetTcbInfoSignature: asnl marshal fail")
	}
	return bytes, nil
}

func CompareTcbComponents(pckComponents []byte, pckpcesvn uint16, tcbComponents []byte, tcbpcesvn uint16) int {
	left_lower := false
	right_lower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		left_lower = true
	}
	if pckpcesvn > tcbpcesvn {
		right_lower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			left_lower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			right_lower = true
		}
	}
	// this should not happen as either one can be greater
	if left_lower && right_lower {
		return Undefined
	}
	if left_lower {
		return Lower
	}
	return EqualOrGreater
}

func GetTcbCompList(TcbLevelList *TcbType) []byte {
	TcbCompLevel := make([]byte, constants.MaxTcbLevels)

	TcbCompLevel[0] = byte(TcbLevelList.SgxTcbComp01Svn)
	TcbCompLevel[1] = byte(TcbLevelList.SgxTcbComp02Svn)
	TcbCompLevel[2] = byte(TcbLevelList.SgxTcbComp03Svn)
	TcbCompLevel[3] = byte(TcbLevelList.SgxTcbComp04Svn)
	TcbCompLevel[4] = byte(TcbLevelList.SgxTcbComp05Svn)
	TcbCompLevel[5] = byte(TcbLevelList.SgxTcbComp06Svn)
	TcbCompLevel[6] = byte(TcbLevelList.SgxTcbComp07Svn)
	TcbCompLevel[7] = byte(TcbLevelList.SgxTcbComp08Svn)
	TcbCompLevel[8] = byte(TcbLevelList.SgxTcbComp09Svn)
	TcbCompLevel[9] = byte(TcbLevelList.SgxTcbComp10Svn)
	TcbCompLevel[10] = byte(TcbLevelList.SgxTcbComp11Svn)
	TcbCompLevel[11] = byte(TcbLevelList.SgxTcbComp12Svn)
	TcbCompLevel[12] = byte(TcbLevelList.SgxTcbComp13Svn)
	TcbCompLevel[13] = byte(TcbLevelList.SgxTcbComp14Svn)
	TcbCompLevel[14] = byte(TcbLevelList.SgxTcbComp15Svn)
	TcbCompLevel[15] = byte(TcbLevelList.SgxTcbComp16Svn)

	return TcbCompLevel
}

func (e *TcbInfoStruct) GetTcbUptoDateStatus(tcbLevels []byte) string {
	PckComponents := tcbLevels[:16]
	PckPceSvn := binary.LittleEndian.Uint16(tcbLevels[16:])

	var Status string
	var TcbComponents []byte
	// iterate through all TCB Levels present in TCBInfo
	for i := 0; i < len(e.TcbInfoData.TcbInfo.TcbLevels); i++ {
		TcbPceSvn := e.TcbInfoData.TcbInfo.TcbLevels[i].Tcb.PceSvn
		TcbComponents = GetTcbCompList(&e.TcbInfoData.TcbInfo.TcbLevels[i].Tcb)
		TcbError := CompareTcbComponents(PckComponents, PckPceSvn, TcbComponents, TcbPceSvn)
		if TcbError == EqualOrGreater {
			Status = e.TcbInfoData.TcbInfo.TcbLevels[i].TcbStatus
			break
		}
	}
	return Status
}

func (e *TcbInfoStruct) DumpTcbInfo() {
	log.Debug("============TCBInfo================")
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
