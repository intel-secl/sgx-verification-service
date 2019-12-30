/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package parser

import (
        "fmt"
        //"bytes"
	"strings"
        "net/http"
	"io/ioutil"
	"crypto/x509"
	"crypto/ecdsa"
        "encoding/hex"
        "encoding/json"

	"github.com/pkg/errors"
        "intel/isecl/svs/resource/utils"
        "intel/isecl/svs/constants"
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
	log.Trace("resource/parser/sgx_qeidentity_parser:NewQeIdentity() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:NewQeIdentity() Leaving")

	obj := new( QeIdentityData )

	client, conf, err := utils.GetHTTPClientObj()
        if err != nil {
		return nil, errors.Wrap(err, "NewQeIdentity: failed to Get client Obj")
        }

        url := fmt.Sprintf("%s/qe/identity", conf.SCSBaseUrl)
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            return nil, errors.Wrap(err, "NewQeIdentity: failed to get new request")
        }

	log.Debug("QEIdentity URL:", url)
        q := req.URL.Query()
        req.URL.RawQuery = q.Encode()

        resp, err := client.Do( req )
        if err != nil {
            return nil, errors.Wrap(err, "NewQeIdentity: failed to to client request")
        }

	if resp.StatusCode !=  200 {
                return nil, errors.New(fmt.Sprintf("NewQeIdentity: Invalid Status code received: %d",resp.StatusCode))
        }

	content, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                        return nil, errors.Wrap(err, "read Response failed ")
        }
        resp.Body.Close()


        if len(content) == 0 {
                return nil, errors.Wrap(err, "NewQeIdentity: buffer lenght is zero")
        }

	obj.RawBlob = make( []byte, len(content))
	copy( obj.RawBlob, content)

        if err := json.Unmarshal(content, &obj.QEJson ); err != nil {
                return nil, errors.Wrap(err, "NewQeIdentity: QeIdentity Unmarshal Failed")
	}

	log.Debug("NewQeIdentity: Headers:", resp.Header)
	certChainList, err := utils.GetCertObjListFromStr( string( resp.Header.Get("Sgx-Qe-Identity-Issuer-Chain") ))
        if err != nil {
                return nil, errors.Wrap(err, "NewQeIdentity: failed to get objects")
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
                return nil, errors.Wrap(err, "NewQeIdentityi: Root CA/Intermediate CA Invalid count")
        }

	return obj, nil
}

func (e *QeIdentityData) GetQEInfoInterCAList()([]*x509.Certificate){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoInterCAList() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoInterCAList() Leaving")

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
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoRootCAList() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoRootCAList() Leaving")

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
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoPublicKey() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoPublicKey() Leaving")

        for _, v := range e.IntermediateCA {
                if strings.Compare( v.Subject.String(), constants.SGXQEInfoSubjectStr ) == 0 {
                        return v.PublicKey.(*ecdsa.PublicKey)
                }
        }
        return nil
}

func (e *QeIdentityData) GetQEInfoBlob()([]byte){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoBlob() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQEInfoBlob() Leaving")

        return e.RawBlob
}

func (e *QeIdentityData) GetQeIdentityStatus() (bool){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdentityStatus() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdentityStatus() Leaving")

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
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdVersion() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdVersion() Leaving")

	return e.QEJson.QeIdentity.Version
}

func (e *QeIdentityData) GetQeIdIssueDate()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIssueDate() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIssueDate() Leaving")

        return e.QEJson.QeIdentity.IssueDate
}

func (e *QeIdentityData) GetQeIdNextUpdate()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdNextUpdate() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdNextUpdate() Leaving")

        return e.QEJson.QeIdentity.NextUpdate
}

func (e *QeIdentityData) GetQeIdMiscSelect()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMiscSelect() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMiscSelect() Leaving")

        return e.QEJson.QeIdentity.MiscSelect
}

func (e *QeIdentityData) GetQeIdMiscSelectMask()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMiscSelectMask() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMiscSelectMask() Leaving")

        return e.QEJson.QeIdentity.MiscSelectMask
}

func (e *QeIdentityData) GetQeIdAttributes()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdAttributes() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdAttributes() Leaving")

	return e.QEJson.QeIdentity.Attributes
}

func (e *QeIdentityData) GetQeIdAttributesMask()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdAttributesMask() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdAttributesMask() Leaving")

	return e.QEJson.QeIdentity.AttributesMask
}

func (e *QeIdentityData) GetQeIdMrSigner()(string){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMrSigner() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdMrSigner() Leaving")

        return e.QEJson.QeIdentity.MrSigner
}

func (e *QeIdentityData) GetQeIdIsvProdId()(uint8){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIsvProdId() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIsvProdId() Leaving")

        return e.QEJson.QeIdentity.IsvProdId
}

func (e *QeIdentityData) GetQeIdIsvSvn()(uint8){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIsvSvn() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdIsvSvn() Leaving")

        return e.QEJson.QeIdentity.IsvSvn
}

func (e *QeIdentityData) GetQeIdSignature()([]byte, error){
	log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdSignature() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:GetQeIdSignature() Leaving")

 	data, err := hex.DecodeString(e.QEJson.Signature)
        if err != nil {
                return nil, errors.Wrap(err, "GetQeIdSignature: error in decode string")
        }
        return data, nil
}

func (e *QeIdentityData) DumpQeIdentity(){
	log.Trace("resource/parser/sgx_qeidentity_parser:DumpQeIdentity() Entering")
	defer log.Trace("resource/parser/sgx_qeidentity_parser:DumpQeIdentity() Leaving")

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

