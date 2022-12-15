/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"intel/isecl/sqvs/v5/resource/domain"
)

type FakePCKCert struct {
}

func NewFakePCKCertObj() domain.PCKCertParser {
	return &FakePCKCert{}
}

func (fe *FakePCKCert) GenPckCertRequiredExtMap()                                     {}
func (fe *FakePCKCert) GenPckCertRequiredSgxExtMap()                                  {}
func (fe *FakePCKCert) GetPckCertRequiredExtMap() map[string]asn1.ObjectIdentifier    { return nil }
func (fe *FakePCKCert) GetPckCertRequiredSgxExtMap() map[string]asn1.ObjectIdentifier { return nil }
func (fe *FakePCKCert) GenCertObj(certBlob []byte) error                              { return nil }
func (fe *FakePCKCert) GetFmspcValue() string                                         { return "" }
func (fe *FakePCKCert) GetPckCertTcbLevels() []byte                                   { return nil }
func (fe *FakePCKCert) ParseFMSPCValue() error                                        { return nil }
func (fe *FakePCKCert) ParseTcbExtensions() error                                     { return nil }
func (fe *FakePCKCert) GetPCKPublicKey() *ecdsa.PublicKey                             { return nil }
func (fe *FakePCKCert) GetPckCrlURL() []string                                        { return nil }

func (fe *FakePCKCert) GetPckCrlObj() []*pkix.CertificateList {

	crlDer, err := hex.DecodeString("308201cc30820173020101300a06082a8648ce3d04030230703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3232303331393134313135315a170d3232303431383134313135315a3081a030330214639f139a5040fdcff191e8a4fb1bf086ed603971170d3232303331393134313135315a300c300a0603551d1504030a01013034021500959d533f9249dc1e513544cdc830bf19b7f1f301170d3232303331393134313135315a300c300a0603551d1504030a0101303302140fda43a00b68ea79b7c2deaeac0b498bdfb2af90170d3232303331393134313135315a300c300a0603551d1504030a0101a02f302d300a0603551d140403020101301f0603551d23041830168014956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d0403020347003044022062f51c1b98adfcb87cb808aaf7a62bc7c79e4c71a6ee4ee130325d8c15b14f8902201908be237ee440008097d6ea978ab1d4ddfa61052ad76fcf0f8d6952861317cd")
	if err != nil {
		fmt.Printf("Failed to decode CRL %v", err)
		return nil
	}
	var pckCRLObjs []*pkix.CertificateList
	crlObj, err := x509.ParseDERCRL(crlDer)
	if err != nil {
		fmt.Printf("Failed to parse DERCRL %v", err)
		return nil
	}

	pckCRLObjs = append(pckCRLObjs, crlObj)
	return pckCRLObjs
}

func (fe *FakePCKCert) GetPckCrlInterCaList() []*x509.Certificate { return nil }
func (fe *FakePCKCert) GetPckCrlRootCaList() []*x509.Certificate  { return nil }
func (fe *FakePCKCert) ParsePckCrl() error                        { return nil }
