/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"strconv"
	"math/big"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"encoding/binary"
        "gopkg.in/restruct.v1"
	"github.com/pkg/errors"

)

type EcdsaQuoteData struct {
	PckCertSize uint32
}

type EpidQuoteData struct {
	Spid [32]byte
}

type SwQuoteData struct {
	Dummy uint32
}

type SkcBlobHeader struct {
	MajorNum	uint32
	MinorNum	uint32
	QuoteSize	uint32
	QuoteType	uint32
	KeyType		uint32
}

type KeyDetailsRSA struct {
	ExponentLen	uint32
	ModulusLen	uint32
}

type KeyDetailsEC struct {
	Dummy	uint32
}

type SkcBlobParsed struct {
	Header		SkcBlobHeader
	RsaKeyDetails	KeyDetailsRSA
	ECKeyDetails	KeyDetailsEC
	EcdsaQuoteInfo  EcdsaQuoteData
	EpidQuoteInfo   EpidQuoteData
	SwQuoteInfo	SwQuoteData
	RawBlobLen	int
	RawBlob		[]byte
	QuoteBlob	[]byte
	PubKeyBlob	[]byte
}

const (
	KeyTypeRsa=1
	KeyTypeEc=2
)

const (
	QuoteTypeEpid = 1
	QuoteTypeEcdsa = 2
	QuoteTypeSw = 3
)

func ParseSkcQuoteBlob( rawBlob string) (*SkcBlobParsed) {
	if len(rawBlob) < 1 {
		log.Debug("ParseSkcBlob Object Spawn: Raw SKC Blob is Empty")
		return nil
	}

	parsedObj := new(SkcBlobParsed)
	_, err := parsedObj.ParseSkcBlobData(rawBlob)
	if err != nil {
		log.Debug("ParseSkcBlob Object Spawn: Raw SKC Parsing Error: ", err.Error())
		return nil
	}
	return parsedObj
}

func (e *SkcBlobParsed) GetKeyType() (uint32) {
	return e.Header.KeyType
}

func (e *SkcBlobParsed) GetQuoteType() (uint32) {
	return e.Header.QuoteType
}

func (e *SkcBlobParsed) GetQuoteBlob() ([]byte) {
	return e.QuoteBlob
}

func (e *SkcBlobParsed) GetQuoteLen() (int) {
	return len(e.QuoteBlob)
}

func (e *SkcBlobParsed) GetPubKeyBlob() ([]byte) {
	return e.PubKeyBlob
}

func (e *SkcBlobParsed) ParseSkcBlobData( blob string) (bool, error) {
	decodedBlob, err := base64.StdEncoding.DecodeString(blob)
        if err != nil {
                log.Error("Failed to Decode Quote")
		return false, errors.Wrap(err, "ParseSkcBlob: Failed to Decode Quote")
        }

	var keyDetailsLen int
	var quoteDetailsLen int
	var pubKeySize	int=0

	e.RawBlob = make([]byte, len(decodedBlob))
	copy(e.RawBlob, decodedBlob)

	e.RawBlobLen  = len(e.RawBlob)
	restruct.Unpack(e.RawBlob, binary.LittleEndian, &e.Header)

	if e.GetKeyType() == KeyTypeRsa {
		log.Debug("ParseSkcBlobData: Rsa Key")
		restruct.Unpack(e.RawBlob[20:], binary.LittleEndian, &e.RsaKeyDetails)
		keyDetailsLen = 8
	}else if e.GetKeyType() == KeyTypeEc {
		log.Debug("ParseSkcBlobData: ECKey Key")
		restruct.Unpack(e.RawBlob[20:], binary.LittleEndian, &e.ECKeyDetails)
		keyDetailsLen = 4
	}else {
		return false, errors.Wrap(err, "ParseSkcBlob: Invalid Key Type Received")
	}

	quoteDetailsOffset := 20 + keyDetailsLen

	if e.GetQuoteType() ==  QuoteTypeEpid {
		restruct.Unpack(e.RawBlob[quoteDetailsOffset:], binary.LittleEndian, &e.EpidQuoteInfo)
		quoteDetailsLen = 32
	} else if e.GetQuoteType() ==  QuoteTypeEcdsa {
		restruct.Unpack(e.RawBlob[quoteDetailsOffset:], binary.LittleEndian, &e.EcdsaQuoteInfo)
		quoteDetailsLen = 32 //Because of union member
	} else if e.GetQuoteType() ==  QuoteTypeSw {
		restruct.Unpack(e.RawBlob[quoteDetailsOffset:], binary.LittleEndian, &e.SwQuoteInfo)
		quoteDetailsLen = 32 //Because of union member
	}else {
		return false, errors.Wrap(err, "ParseSkcBlob: Invalid Quote Type Received")
	}

	pubKeyStrOfset := quoteDetailsOffset + quoteDetailsLen
	quoteStrOffset := quoteDetailsOffset + quoteDetailsLen
	if e.GetQuoteType() ==  QuoteTypeEcdsa {
		quoteStrOffset = quoteStrOffset + int(e.EcdsaQuoteInfo.PckCertSize)
		pubKeyStrOfset = pubKeyStrOfset + int(e.EcdsaQuoteInfo.PckCertSize)
	}

	if e.GetKeyType() == KeyTypeRsa {
		pubKeySize =  (int(e.RsaKeyDetails.ModulusLen) + int(e.RsaKeyDetails.ExponentLen))
		quoteStrOffset = quoteStrOffset + pubKeySize
	} else {
		quoteStrOffset += 8 //Because of union member
	}

	pubKeyEndOffset := pubKeyStrOfset + pubKeySize
	e.PubKeyBlob = make([]byte, pubKeySize)
	copy( e.PubKeyBlob,  e.RawBlob[pubKeyStrOfset: pubKeyEndOffset])

	quoteEndOffset := quoteStrOffset + int(e.Header.QuoteSize)
	log.Debug("TotalBlobSize: ", e.RawBlobLen,", QuoteStrOffset: ", quoteStrOffset, ", QuoteEndOffet: ", quoteEndOffset)

	e.QuoteBlob = make([]byte, e.Header.QuoteSize)
	copy( e.QuoteBlob,  e.RawBlob[quoteStrOffset:])

	log.Debug("QuoteSize: ", len(e.QuoteBlob))

	e.DumpSkcBlobHeader()
	return true, nil
}

func (e *SkcBlobParsed) DumpSkcBlobHeader() {
	log.Debugf("===================================>SkcQuoteBlobHeader<=======================================")
	log.Debug("Header->MajorNum = ", e.Header.MajorNum)
	log.Debug("Header->MinorNum = ", e.Header.MinorNum)
	log.Debug("Header->QuoteSize = ", e.Header.QuoteSize)
	log.Debug("Header->QuoteType = ", e.Header.QuoteType)
	log.Debug("Header->KeyType = ", e.Header.KeyType)

	if e.GetKeyType() == KeyTypeRsa {
		log.Debug("RSAKeyDetails->ModulusLen = ", e.RsaKeyDetails.ModulusLen)
		log.Debug("RSAKeyDetails->ExponentLen = ", e.RsaKeyDetails.ExponentLen)
	} else {
		log.Debug("ECKeyDetails->ModulusLen = ", e.ECKeyDetails.Dummy)
	}

	if e.GetQuoteType() ==  QuoteTypeEpid {
		log.Debug("EpidQuoteInfo->Spid = ", e.EpidQuoteInfo.Spid)
	} else if e.GetQuoteType() ==  QuoteTypeEcdsa {
		log.Debug("EcdsaQuoteInfo->PckCertSize = ", e.EcdsaQuoteInfo.PckCertSize)
	} else if e.GetQuoteType() ==  QuoteTypeSw{
		log.Debug("SwQuoteInfo->Dummy = ", e.SwQuoteInfo.Dummy)
	}
}

func (e *SkcBlobParsed) GetRSAModulusLen() (uint32) {
	if e.GetKeyType() == KeyTypeRsa {
		return e.RsaKeyDetails.ModulusLen
	}
	log.Error("GetRSAModulusLen: Invalid Key type")
	return 0
}

func (e *SkcBlobParsed) GetRSAExponentLen() (uint32) {
	if e.GetKeyType() == KeyTypeRsa {
		return e.RsaKeyDetails.ExponentLen
	}
	log.Error("GetRSAModulusLen: Invalid Key type")
	return 0
}

func (e *SkcBlobParsed) GetRSAPubKeyObj()([]byte, error) {
	var err error
	if e.GetKeyType() != KeyTypeRsa {
		return nil, errors.Wrap(err, "GetRSAPubKeyObj: Invalid Public Key Type")
	}

	pubKeyBlob :=  e.GetPubKeyBlob()
	if len(pubKeyBlob) == 0{
		return nil, errors.Wrap(err, "GetRSAPubKeyObj: Invalid Public Key length")
	}

	exponentLen := int(e.GetRSAExponentLen())
	exponentArr := pubKeyBlob[:exponentLen]
	modulusStrOffset := exponentLen

	n := big.Int{}
        n.SetBytes(pubKeyBlob[modulusStrOffset:])
	eb := big.Int{}
	eb.SetBytes(exponentArr)

	ex, err := strconv.Atoi(eb.String())
	if err != nil {
		return nil, errors.Wrap(err, "GetRSAPubKeyObj: Strconv to int")
	}

	pubKey := rsa.PublicKey {N: &n, E: int(ex)}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "GetRSAPubKeyObj: Marshal error")
	}

	rsaPem := pem.Block {Type : "PUBLIC KEY", Bytes : pubKeyBytes}
	rsaBytes := pem.EncodeToMemory(&rsaPem)
	if rsaBytes == nil {
		return nil, errors.Wrap(err, "GetRSAPubKeyObj: Pem Encode failed")
	}

	return rsaBytes, nil
}
