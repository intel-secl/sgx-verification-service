/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package parser

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"unsafe"
)

type SkcBlobParsed struct {
	QuoteBlob []byte
}

func ParseSkcQuoteBlob(rawBlob string) *SkcBlobParsed {
	if len(rawBlob) < int(unsafe.Sizeof(SkcBlobParsed{})) {
		log.Error("ParseSkcQuoteBlob: SKC Blob is Empty")
		return nil
	}

	parsedObj := new(SkcBlobParsed)
	_, err := parsedObj.parseSkcBlobData(rawBlob)
	if err != nil {
		log.Error("parseSkcBlobData: SKC Blob Parsing Error: ", err.Error())
		return nil
	}
	return parsedObj
}

func ParseQuoteBlob(rawBlob string) *SkcBlobParsed {
	log.Trace("parser/skc_quote_parser:ParseQuoteBlob() Entering")
	defer log.Trace("parser/skc_quote_parser:ParseQuoteBlob() Leaving")
	if len(rawBlob) < int(unsafe.Sizeof(SkcBlobParsed{})) {
		log.Error("ParseQuoteBlob: SKC Blob is Empty")
		return nil
	}
	parsedObj := new(SkcBlobParsed)
	decodedBlob, err := base64.StdEncoding.DecodeString(rawBlob)
	if err != nil {
		log.Error("Failed to Base64 Decode Quote")
		return nil
	}
	quoteSize := len(decodedBlob)
	parsedObj.QuoteBlob = make([]byte, quoteSize)
	copy(parsedObj.QuoteBlob, decodedBlob)
	return parsedObj
}

func (e *SkcBlobParsed) GetQuoteBlob() []byte {
	return e.QuoteBlob
}

func (e *SkcBlobParsed) parseSkcBlobData(blob string) (bool, error) {
	log.Debug(blob)
	decodedBlob, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		log.Error("Failed to Base64 Decode Quote")
		return false, errors.Wrap(err, "ParseSkcBlob: Failed to Base64 Decode Quote")
	}

	// invoke golang in-built recover() function to recover from the panic
	// recover function will receive the error from out of bound slice access
	// and will prevent the program from crashing
	defer func() {
		if perr := recover(); perr != nil {
			log.Error("ParseSkcBlob: slice out of bound access")
		}
	}()

	e.QuoteBlob = make([]byte, len(decodedBlob))
	copy(e.QuoteBlob, decodedBlob)

	return true, nil
}
