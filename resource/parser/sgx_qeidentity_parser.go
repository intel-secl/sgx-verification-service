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
	"crypto/x509"
	"crypto/ecdsa"
        "encoding/hex"
        "encoding/json"

        "intel/isecl/svs/resource/utils"
        "intel/isecl/svs/constants"
        log "github.com/sirupsen/logrus"
)

type QeIdentityJson struct {
        QeIdentity      QeIdentityType
        Signature       string          `json: "signature"`
}

type QeIdentityData struct {
 	QEJson		QeIdentityJson	
	RootCA          map[string]*x509.Certificate
        IntermediateCA  map[string]*x509.Certificate
        RawBlob         []byte
}

type QeIdentityType struct {
        Version         uint8   `json: "version"`
        IssueDate       string  `json: "issueDate"`
        NextUpdate      string  `json: "nextUpdate"`
        MiscSelect      string  `json: "miscselect"`
        MiscSelectMask  string  `json: "miscselectMask"`
        Attributes      string  `json: "attributes"`
        AttributesMask  string  `json: "attributesMask"`
        MrSigner        string  `json: "mrsigner"`
        IsvProdId       uint8   `json: "isvprodid"`
        IsvSvn          uint8   `json: "isvsvn"`
}

func NewQeIdentity() (*QeIdentityData, error) {

	obj := new( QeIdentityData )

	client, conf, err := utils.GetHTTPClientObj()
        if err != nil {
		return nil, errors.New("NewQeIdentity: failed to Get client Obj: " + err.Error())
        }

        url := fmt.Sprintf("%s/qe/identity", conf.SCSBaseUrl)
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            return nil, errors.New("NewQeIdentity: " + err.Error())
        }

	log.Debug("QEIdentity URL:", url)
        q := req.URL.Query()
        req.URL.RawQuery = q.Encode()

        resp, err := client.Do( req )
        if err != nil {
            return nil, errors.New("NewQeIdentity: " + err.Error())
        }

	if resp.StatusCode !=  200 {
                return nil, errors.New(fmt.Sprintf("NewQeIdentity: Invalid Status code received: %d",resp.StatusCode))
        }

	buf := new(bytes.Buffer)
        buf.ReadFrom(resp.Body)


        if len(buf.Bytes()) == 0 {
                return nil, errors.New("NewQeIdentity: " + err.Error())
        }

	obj.RawBlob = make( []byte, len(buf.Bytes()))
	copy( obj.RawBlob, buf.Bytes())

        if err := json.Unmarshal(buf.Bytes(), &obj.QEJson ); err != nil {
                return nil, errors.New("NewQeIdentity: QeIdentity Unmarshal Failed" + err.Error())
	}

	log.Debug("NewQeIdentity: Headers:", resp.Header)
	certChainList, err := utils.GetCertObjListFromStr( string( resp.Header.Get("Sgx-Qe-Identity-Issuer-Chain") ))
        if err != nil {
                return nil, errors.New("NewQeIdentity: "+err.Error())
        }


	obj.RootCA = make( map[string]*x509.Certificate )
        obj.IntermediateCA = make( map[string]*x509.Certificate )

        var IntermediateCACount int=0
        var RootCACount int=0
        for i:=0;i<len(certChainList);i++ {
                cert := certChainList[i]
                if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
                        RootCACount += 1
                        obj.RootCA[cert.Subject.String()] = cert
                }
                if strings.Contains(cert.Subject.String(), "CN=Intel SGX TCB Signing"){
                        IntermediateCACount += 1
                        obj.IntermediateCA[cert.Subject.String()] = cert
                }
                log.Debug("Cert[" ,i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
        }

        if IntermediateCACount == 0 || RootCACount == 0 {
                return nil, errors.New("NewQeIdentity - Root CA/Intermediate CA Invalid count")
        }

	return obj, nil
}

func (e *QeIdentityData) GetQEInfoInterCAList()([]*x509.Certificate){
        interMediateCAArr := make( []*x509.Certificate, len(e.IntermediateCA))
        var i  int=0
        for _, v := range e.IntermediateCA {
                interMediateCAArr[i] = v
                i += 1
        }
        log.Debug("GetQEInfoInterCAList:", len(interMediateCAArr))
        return interMediateCAArr
}

func (e *QeIdentityData) GetQEInfoRootCAList()([]*x509.Certificate){
        RootCAArr := make( []*x509.Certificate, len(e.RootCA))
        var i  int=0
        for _, v := range e.RootCA {
                RootCAArr[i] = v
                i += 1
        }
        log.Debug("GetQEInfoRootCAList:", len(RootCAArr))
        return RootCAArr
}

func (e *QeIdentityData) GetQEInfoPublicKey()( *ecdsa.PublicKey){
        for _, v := range e.IntermediateCA {
                if strings.Compare( v.Subject.String(), constants.SGXQEInfoSubjectStr ) == 0 {
                        return v.PublicKey.(*ecdsa.PublicKey)
                }
        }
        return nil
}
func (e *QeIdentityData) GetQEInfoBlob()([]byte){
        return e.RawBlob
}




func (e *QeIdentityData) GetQeIdentityStatus() (bool){
	sign, _ :=   e.GetQeIdSignature()
	if  !utils.IntToBool(int(e.GetQeIdVersion()))    || !utils.IntToBool(len(e.GetQeIdIssueDate()))      ||
	    !utils.IntToBool(len(e.GetQeIdMiscSelect())) || !utils.IntToBool(len(e.GetQeIdMiscSelectMask())) || 
	    !utils.IntToBool(len(e.GetQeIdAttributes())) || !utils.IntToBool(len(e.GetQeIdAttributesMask())) || 
	    !utils.IntToBool(len(e.GetQeIdMrSigner()))   || !utils.IntToBool(int(e.GetQeIdIsvProdId()))      || 
	    !utils.IntToBool(int(e.GetQeIdIsvSvn()))     || !utils.IntToBool(len(sign)) {
		return false
	}
	return true
}

func (e *QeIdentityData) GetQeIdVersion()(uint8){
	return e.QEJson.QeIdentity.Version
}

func (e *QeIdentityData) GetQeIdIssueDate()(string){
        return e.QEJson.QeIdentity.IssueDate
}

func (e *QeIdentityData) GetQeIdNextUpdate()(string){
        return e.QEJson.QeIdentity.NextUpdate
}

func (e *QeIdentityData) GetQeIdMiscSelect()(string){
        return e.QEJson.QeIdentity.MiscSelect
}

func (e *QeIdentityData) GetQeIdMiscSelectMask()(string){
        return e.QEJson.QeIdentity.MiscSelectMask
}

func (e *QeIdentityData) GetQeIdAttributes()(string){
	return e.QEJson.QeIdentity.Attributes
}

func (e *QeIdentityData) GetQeIdAttributesMask()(string){
	return e.QEJson.QeIdentity.AttributesMask
}

func (e *QeIdentityData) GetQeIdMrSigner()(string){
        return e.QEJson.QeIdentity.MrSigner
}

func (e *QeIdentityData) GetQeIdIsvProdId()(uint8){
        return e.QEJson.QeIdentity.IsvProdId
}

func (e *QeIdentityData) GetQeIdIsvSvn()(uint8){
        return e.QEJson.QeIdentity.IsvSvn
}

func (e *QeIdentityData) GetQeIdSignature()([]byte, error){
 	data, err := hex.DecodeString(e.QEJson.Signature)
        if err != nil {
                return nil, errors.New("GetQeIdSignature: error in decode string")
        }
        return data, nil
}

func (e *QeIdentityData) DumpQeIdentity(){
        log.Debug("===========QEIdentity==============")
        log.Printf("Version: %v", e.QEJson.QeIdentity.Version)
        log.Printf("IssueDate: %v", e.QEJson.QeIdentity.IssueDate)
        log.Printf("NextUpdate: %v", e.QEJson.QeIdentity.NextUpdate)
        log.Printf("miscselect: %v", e.QEJson.QeIdentity.MiscSelect)
        log.Printf("miscselectMask: %v", e.QEJson.QeIdentity.MiscSelectMask)
        log.Printf("attributes: %v", e.QEJson.QeIdentity.Attributes)
        log.Printf("attributesMask: %v", e.QEJson.QeIdentity.AttributesMask)
        log.Printf("mrsigner: %v", e.QEJson.QeIdentity.MrSigner)
        log.Printf("isvprodid: %v", e.QEJson.QeIdentity.IsvProdId)
        log.Printf("isvsvn: %v", e.QEJson.QeIdentity.IsvSvn)
        log.Printf("Signature: %v", e.QEJson.Signature)
}

