/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package parser

import (
	"fmt"
	"bytes"
	"errors"
	"strings"
	"net/http"
	"math/big"
	"crypto/x509"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/asn1"
	"encoding/json"

	"intel/isecl/svs/constants"
	"intel/isecl/svs/resource/utils"

        log "github.com/sirupsen/logrus"
)

type TcbType struct {
        Sgxtcbcomp01svn int		`json: "sgxtcbcomp01svn"`
        Sgxtcbcomp02svn int		`json: "sgxtcbcomp02svn"`
        Sgxtcbcomp03svn int		`json: "sgxtcbcomp03svn"`
        Sgxtcbcomp04svn int		`json: "sgxtcbcomp04svn"`
        Sgxtcbcomp05svn int		`json: "sgxtcbcomp05svn"`
        Sgxtcbcomp06svn int		`json: "sgxtcbcomp06svn"`
        Sgxtcbcomp07svn int		`json: "sgxtcbcomp07svn"`
        Sgxtcbcomp08svn int		`json: "sgxtcbcomp08svn"`
        Sgxtcbcomp09svn int		`json: "sgxtcbcomp09svn"`
        Sgxtcbcomp10svn int		`json: "sgxtcbcomp10svn"`
        Sgxtcbcomp11svn int		`json: "sgxtcbcomp11svn"`
        Sgxtcbcomp12svn int		`json: "sgxtcbcomp12svn"`
        Sgxtcbcomp13svn int		`json: "sgxtcbcomp13svn"`
        Sgxtcbcomp14svn int		`json: "sgxtcbcomp14svn"`
        Sgxtcbcomp15svn int		`json: "sgxtcbcomp15svn"`
        Sgxtcbcomp16svn int		`json: "sgxtcbcomp16svn"`
        Pcesvn 		int		`json: "pcesvn"`
}

type TcbLevelsType struct {
	Tcb     	TcbType 	`json: "tcb"`
	Status  	string  	`json: "status"`
}

type TcbInfoType struct {
	Version         int             `json:"version"`
        IssueDate       string          `json:"issueDate"`
        NextUpdate      string          `json:"nextUpdate"`
        Fmspc           string          `json:"fmspc"`
        PceId           string          `json:"pceId"`
        TcbLevels       []TcbLevelsType `json: "tcbLevels"`
}

type TcbInfoJson struct {
        TcbInfo 	TcbInfoType
        Signature 	string		`json:"signature"`
}

type TcbInfoStruct struct {
	TcbInfoData     TcbInfoJson
	RootCA 		map[string]*x509.Certificate
	IntermediateCA 	map[string]*x509.Certificate
	RawBlob		[]byte
}
type ECDSASignature struct {
    R, S *big.Int
}


func NewTCBInfo(fmspc string) (*TcbInfoStruct, error) {

	if len(fmspc) < 0 {
                return nil, errors.New("NewTCBInfo: FMSPC is Empty")
        }

	tcbInfoStruct := new(TcbInfoStruct)
	err := tcbInfoStruct.GetTcbInfoStruct(fmspc)
	if err != nil {
		return nil, err
	}
	return tcbInfoStruct, nil
}

func (e *TcbInfoStruct) GetTCBInfoInterCAList()([]*x509.Certificate){
        interMediateCAArr := make( []*x509.Certificate, len(e.IntermediateCA))
        var i  int=0
        for _, v := range e.IntermediateCA {
                interMediateCAArr[i] = v
                i += 1
        }
        return interMediateCAArr
}

func (e *TcbInfoStruct) GetTCBInfoRootCAList()([]*x509.Certificate){
        RootCAArr := make( []*x509.Certificate, len(e.RootCA))
        var i  int=0
        for _, v := range e.RootCA {
                RootCAArr[i] = v
                i += 1
        }
        log.Debug("GetTCBInfoRootCAList:", len(RootCAArr))
        return RootCAArr
}

func (e *TcbInfoStruct) GetTCBInfoPublicKey()( *ecdsa.PublicKey){
        for _, v := range e.IntermediateCA{
		if strings.Compare( v.Subject.String(), constants.SGXTCBInfoSubjectStr ) == 0 {
			return v.PublicKey.(*ecdsa.PublicKey)
		}
		utils.DumpDataInHex("Signature:", v.Signature, len(v.Signature))
        }
	log.Error("GetTCBInfoPublicKey: Public Key not found\n")
	return nil
}

func (e *TcbInfoStruct) GetTcbInfoIssueDate()( string ){
	return e.TcbInfoData.TcbInfo.IssueDate
}

func (e *TcbInfoStruct) GetTcbInfoNextUpdate()( string ){
	return e.TcbInfoData.TcbInfo.NextUpdate
}

func (e *TcbInfoStruct) GetTcbInfoStruct(fmspc string)(error) {

	client, conf, err := utils.GetHTTPClientObj()
        if err != nil {
		return errors.New("NewTCBInfo: Failed to Get client Obj: " + err.Error())
        }

	url := fmt.Sprintf("%s/tcb", conf.SCSBaseUrl)
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return errors.New("GetTcbInfoJson: Failed to Get http NewRequest: "+err.Error())
        }


        q := req.URL.Query()
        q.Add("fmspc", fmspc)

        req.URL.RawQuery = q.Encode()
        resp, err := client.Do( req )
        if err != nil {
                return errors.New("GetTcbInfoJson: Failed to Get http client: "+err.Error())
        }

	if resp.StatusCode !=  200 {
                return errors.New(fmt.Sprintf("GetTcbInfoJson: Invalid Status code received: %d",resp.StatusCode))
	}
        buf := new(bytes.Buffer)
        buf.ReadFrom(resp.Body)

	e.RawBlob =  make( []byte, resp.ContentLength)
	copy( e.RawBlob, buf.Bytes())

	log.Debug("GetTcbInfoJson: blob[",resp.ContentLength,"]:", len(e.RawBlob))
	
        certChainList, err := utils.GetCertObjListFromStr( string( resp.Header.Get("SGX-TCB-Info-Issuer-Chain") ))
        if err != nil {
                return errors.New("GetTcbInfoJson: "+err.Error())
        }

        if err := json.Unmarshal(buf.Bytes(), &e.TcbInfoData); err != nil {
                return errors.New("TCBInfo Unmarshal Failed" + err.Error())
	}

        e.RootCA = make( map[string]*x509.Certificate )
        e.IntermediateCA = make( map[string]*x509.Certificate )

        var IntermediateCACount int=0
        var RootCACount int=0
        for i:=0;i<len(certChainList);i++ {
                cert := certChainList[i]
                if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
                        RootCACount += 1
                        e.RootCA[cert.Subject.String()] = cert
                }
                if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing"){
                        IntermediateCACount += 1
                        e.IntermediateCA[cert.Subject.String()] = cert
                }
                log.Debug("Cert[" ,i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
        }

        if IntermediateCACount == 0 || RootCACount == 0 {
                return errors.New("TCB INFO - Root CA/Intermediate CA Invalid count\n")
        }

	return nil
}

func (e *TcbInfoStruct) GetTcbInfoFmspc()(string){
        return e.TcbInfoData.TcbInfo.Fmspc
}


func (e *TcbInfoStruct) GetTcbInfoBlob()([]byte){
	bytes, err := json.Marshal(e.TcbInfoData.TcbInfo)
    	if err != nil {
        	log.Debug("GetTcbInfoBlob: Error in Marshal")
    	}
	return bytes
}


func (e *TcbInfoStruct) GetTcbInfoSignature()([]byte, error){
	signatureBytes, err := hex.DecodeString(e.TcbInfoData.Signature)
	if err != nil {
    		return nil, errors.New("GetTcbInfoSignature: error in decode string")
	}

	rBytes, sBytes  := signatureBytes[:32], signatureBytes[32:]
        bytes, err :=  asn1.Marshal(ECDSASignature{R : new(big.Int).SetBytes(rBytes), S:new(big.Int).SetBytes(sBytes)})
        if err!=nil {
    		return nil, errors.New("GetTcbInfoSignature: "+ err.Error())
        }
        return bytes, nil
}

func (e *TcbInfoStruct) GetTcbInfoStatus()(string){
        return e.TcbInfoData.TcbInfo.TcbLevels[0].Status
}


func (e *TcbInfoStruct) DumpTcbInfo(){
        log.Debug("============TCBInfo================")
        log.Printf("Version:         %v", e.TcbInfoData.TcbInfo.Version)
        log.Printf("IssueDate:       %v", e.TcbInfoData.TcbInfo.IssueDate)
        log.Printf("NextUpdate:      %v", e.TcbInfoData.TcbInfo.NextUpdate)
        log.Printf("Fmspc:           %v", e.TcbInfoData.TcbInfo.Fmspc)
        log.Printf("pceId:           %v", e.TcbInfoData.TcbInfo.PceId)
        log.Printf("Sgxtcbcomp01svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp01svn)
        log.Printf("Sgxtcbcomp02svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp02svn)
        log.Printf("Sgxtcbcomp03svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp03svn)
        log.Printf("Sgxtcbcomp04svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp04svn)
        log.Printf("Sgxtcbcomp05svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp05svn)
        log.Printf("Sgxtcbcomp06svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp06svn)
        log.Printf("Sgxtcbcomp07svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp07svn)
        log.Printf("Sgxtcbcomp08svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp08svn)
        log.Printf("Sgxtcbcomp09svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp09svn)
        log.Printf("Sgxtcbcomp10svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp10svn)
        log.Printf("Sgxtcbcomp11svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp11svn)
        log.Printf("Sgxtcbcomp12svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp12svn)
        log.Printf("Sgxtcbcomp13svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp13svn)
        log.Printf("Sgxtcbcomp14svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp14svn)
        log.Printf("Sgxtcbcomp15svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp15svn)
        log.Printf("Sgxtcbcomp16svn: %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Sgxtcbcomp16svn)
        log.Printf("Status:          %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Status)
        log.Printf("Pcesvn:          %v", e.TcbInfoData.TcbInfo.TcbLevels[0].Tcb.Pcesvn)
        log.Printf("Signature:       %v", e.TcbInfoData.Signature)
}

