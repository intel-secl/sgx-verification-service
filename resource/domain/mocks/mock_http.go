/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"intel/isecl/sqvs/v5/resource/domain"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	certFilePath = "../test/testcert.pem"
)

type ClientMock struct {
	ResponseCode int
}

var qeInfo = []byte(`{
	"enclaveIdentity": {
		"id": "QE",
		"version": 2,
		"issueDate": "2020-06-15T06:42:01Z",
		"nextUpdate": "2020-07-15T06:42:01Z",
		"tcbEvaluationDataNumber": 5,
		"miscselect": "00000000",
		"miscselectMask": "FFFFFFFF",
		"attributes": "11000000000000000000000000000000",
		"attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
		"mrsigner": "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF",
		"isvprodid": 1,
		"tcbLevels": [
			{
				"tcb": {
					"isvsvn": 2
				},
				"tcbDate": "2019-05-15T00:00:00Z",
				"tcbStatus": "UpToDate"
			},
			{
				"tcb": {
					"isvsvn": 1
				},
				"tcbDate": "2018-08-15T00:00:00Z",
				"tcbStatus": "OutOfDate"
			}
		]
	},
	"signature": "2c50f0f4297781594e4d86c864ef1bd6797ab77566c9ddc417330ca7f37456f2f998a44e8230c57c2c8f51258ce5044cf0ac0af58e5c953e466f51981dc1390c"
}`)

var tcbInfoJson = []byte(`{
	"tcbInfo": {
		"version": 2,
		"issueDate": "2020-06-15T06:42:01Z",
		"nextUpdate": "2020-07-15T06:42:01Z",
		"fmspc": "20606a000000",
		"pceId": "0000",
		"tcbType": 0,
		"tcbEvaluationDataNumber": 5,
		"tcbLevels": [
			{
				"tcb": {
					"sgxtcbcomp01svn": 2,
					"sgxtcbcomp02svn": 2,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 10
				},
				"tcbDate": "2020-05-28T00:00:00Z",
				"tcbStatus": "UpToDate"
			},
			{
				"tcb": {
					"sgxtcbcomp01svn": 1,
					"sgxtcbcomp02svn": 1,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 9
				},
				"tcbDate": "2020-03-22T00:00:00Z",
				"tcbStatus": "OutOfDate"
			},
			{
				"tcb": {
					"sgxtcbcomp01svn": 1,
					"sgxtcbcomp02svn": 1,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 0
				},
				"tcbDate": "2020-03-22T00:00:00Z",
				"tcbStatus": "OutOfDate"
			}
		]
	},
	"signature": "40b3536ee9c7028df7f0a976eaa405bc82768a258512be95fd151731f756f20a35c4a2642b91ba8083dca067932af75f1f92265dbdbd12573b05a959f6e3a677"
}`)

func NewClientMock(respCode int) domain.HttpClient {
	return &ClientMock{
		ResponseCode: respCode,
	}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {

	respHeader := http.Header{}

	if strings.Contains(req.URL.String(), "/qe/identity") && c.ResponseCode == 200 {
		respHeader.Add("Sgx-Qe-Identity-Issuer-Chain", "-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJqgAwIBAgIUb6rZwuxZc5cIkp6%2Foqqz7HdGyFwwCgYIKoZIzj0EAwIw%0AcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR%0ASW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI%0ADAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNjIxMTEyNDU2WhcNMjkwNjIxMTEyNDU2%0AWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK%0ADBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV%0ABAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOB3%0AWFm1ziJAlu79StgxfAuz8AWCkoiraneuAGgrFExeiukczJvjWdtDTM2O7w8GiZAt%0A1h84AyDRUb%2BHoNaflACjggMQMIIDDDAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3g%0ADwcrVyQqtzBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3NieC5hcGkudHJ1c3Rl%0AZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw%2F%0AY2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQ6mE6WHjgoVSRiUaG%2F%0A0QmQDpX7LjAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAjkGCSqGSIb4%0ATQENAQSCAiowggImMB4GCiqGSIb4TQENAQEEEGzzoSC5Btq3aBE%2BWYxHhwUwggFj%0ABgoqhkiG%2BE0BDQECMIIBUzAQBgsqhkiG%2BE0BDQECAQIBATAQBgsqhkiG%2BE0BDQEC%0AAgIBATAQBgsqhkiG%2BE0BDQECAwIBADAQBgsqhkiG%2BE0BDQECBAIBADAQBgsqhkiG%0A%2BE0BDQECBQIBADAQBgsqhkiG%2BE0BDQECBgIBADAQBgsqhkiG%2BE0BDQECBwIBADAQ%0ABgsqhkiG%2BE0BDQECCAIBADAQBgsqhkiG%2BE0BDQECCQIBADAQBgsqhkiG%2BE0BDQEC%0ACgIBADAQBgsqhkiG%2BE0BDQECCwIBADAQBgsqhkiG%2BE0BDQECDAIBADAQBgsqhkiG%0A%2BE0BDQECDQIBADAQBgsqhkiG%2BE0BDQECDgIBADAQBgsqhkiG%2BE0BDQECDwIBADAQ%0ABgsqhkiG%2BE0BDQECEAIBADAQBgsqhkiG%2BE0BDQECEQIBCTAfBgsqhkiG%2BE0BDQEC%0AEgQQAQEAAAAAAAAAAAAAAAAAADAQBgoqhkiG%2BE0BDQEDBAIAADAUBgoqhkiG%2BE0B%0ADQEEBAYQYGoAAAAwDwYKKoZIhvhNAQ0BBQoBATAeBgoqhkiG%2BE0BDQEGBBDjJ4f6%0AieS5MJrtZWT28t9KMEQGCiqGSIb4TQENAQcwNjAQBgsqhkiG%2BE0BDQEHAQEB%2FzAQ%0ABgsqhkiG%2BE0BDQEHAgEBADAQBgsqhkiG%2BE0BDQEHAwEB%2FzAKBggqhkjOPQQDAgNI%0AADBFAiBJwRZ5Dkvmz41SMH%2FFojZqiPxfzpQo78iqcvTdo0DwTQIhAPzZkuFcwZUV%0Al0yBja8lgLWp%2F8eMKpx5hOAw1dDV2iST%0A-----END%20CERTIFICATE-----%0A")
		return &http.Response{
			StatusCode: c.ResponseCode,
			Body:       ioutil.NopCloser(bytes.NewReader(qeInfo)),
			Header:     respHeader,
		}, nil
	}
	// /tcb
	if strings.Contains(req.URL.String(), "/tcb") && c.ResponseCode == 200 {
		respHeader.Add("SGX-TCB-Info-Issuer-Chain", "-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJqgAwIBAgIUb6rZwuxZc5cIkp6%2Foqqz7HdGyFwwCgYIKoZIzj0EAwIw%0AcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR%0ASW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI%0ADAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNjIxMTEyNDU2WhcNMjkwNjIxMTEyNDU2%0AWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK%0ADBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV%0ABAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOB3%0AWFm1ziJAlu79StgxfAuz8AWCkoiraneuAGgrFExeiukczJvjWdtDTM2O7w8GiZAt%0A1h84AyDRUb%2BHoNaflACjggMQMIIDDDAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3g%0ADwcrVyQqtzBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3NieC5hcGkudHJ1c3Rl%0AZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw%2F%0AY2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQ6mE6WHjgoVSRiUaG%2F%0A0QmQDpX7LjAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAjkGCSqGSIb4%0ATQENAQSCAiowggImMB4GCiqGSIb4TQENAQEEEGzzoSC5Btq3aBE%2BWYxHhwUwggFj%0ABgoqhkiG%2BE0BDQECMIIBUzAQBgsqhkiG%2BE0BDQECAQIBATAQBgsqhkiG%2BE0BDQEC%0AAgIBATAQBgsqhkiG%2BE0BDQECAwIBADAQBgsqhkiG%2BE0BDQECBAIBADAQBgsqhkiG%0A%2BE0BDQECBQIBADAQBgsqhkiG%2BE0BDQECBgIBADAQBgsqhkiG%2BE0BDQECBwIBADAQ%0ABgsqhkiG%2BE0BDQECCAIBADAQBgsqhkiG%2BE0BDQECCQIBADAQBgsqhkiG%2BE0BDQEC%0ACgIBADAQBgsqhkiG%2BE0BDQECCwIBADAQBgsqhkiG%2BE0BDQECDAIBADAQBgsqhkiG%0A%2BE0BDQECDQIBADAQBgsqhkiG%2BE0BDQECDgIBADAQBgsqhkiG%2BE0BDQECDwIBADAQ%0ABgsqhkiG%2BE0BDQECEAIBADAQBgsqhkiG%2BE0BDQECEQIBCTAfBgsqhkiG%2BE0BDQEC%0AEgQQAQEAAAAAAAAAAAAAAAAAADAQBgoqhkiG%2BE0BDQEDBAIAADAUBgoqhkiG%2BE0B%0ADQEEBAYQYGoAAAAwDwYKKoZIhvhNAQ0BBQoBATAeBgoqhkiG%2BE0BDQEGBBDjJ4f6%0AieS5MJrtZWT28t9KMEQGCiqGSIb4TQENAQcwNjAQBgsqhkiG%2BE0BDQEHAQEB%2FzAQ%0ABgsqhkiG%2BE0BDQEHAgEBADAQBgsqhkiG%2BE0BDQEHAwEB%2FzAKBggqhkjOPQQDAgNI%0AADBFAiBJwRZ5Dkvmz41SMH%2FFojZqiPxfzpQo78iqcvTdo0DwTQIhAPzZkuFcwZUV%0Al0yBja8lgLWp%2F8eMKpx5hOAw1dDV2iST%0A-----END%20CERTIFICATE-----%0A")
		return &http.Response{
			StatusCode: c.ResponseCode,
			Body:       ioutil.NopCloser(bytes.NewReader(tcbInfoJson)),
			Header:     respHeader,
		}, nil
	}

	if c.ResponseCode == 400 {
		return &http.Response{
			StatusCode: c.ResponseCode,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			Header:     respHeader,
		}, errors.New("Bad request")
	}

	if c.ResponseCode == 401 {
		return &http.Response{
			StatusCode: c.ResponseCode,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			Header:     respHeader,
		}, nil
	}

	if c.ResponseCode == 204 {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			Header:     respHeader,
		}, nil
	}

	if c.ResponseCode == 202 {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte("testResponse"))),
			Header:     respHeader,
		}, nil
	}

	crlBytes, err := hex.DecodeString("308201cc30820173020101300a06082a8648ce3d04030230703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3232303331393134313135315a170d3232303431383134313135315a3081a030330214639f139a5040fdcff191e8a4fb1bf086ed603971170d3232303331393134313135315a300c300a0603551d1504030a01013034021500959d533f9249dc1e513544cdc830bf19b7f1f301170d3232303331393134313135315a300c300a0603551d1504030a0101303302140fda43a00b68ea79b7c2deaeac0b498bdfb2af90170d3232303331393134313135315a300c300a0603551d1504030a0101a02f302d300a0603551d140403020101301f0603551d23041830168014956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d0403020347003044022062f51c1b98adfcb87cb808aaf7a62bc7c79e4c71a6ee4ee130325d8c15b14f8902201908be237ee440008097d6ea978ab1d4ddfa61052ad76fcf0f8d6952861317cd")
	if err != nil {
		return nil, errors.New("failed to decode hex string")
	}

	crlEnodedString := base64.StdEncoding.EncodeToString(crlBytes)

	SGXPCKCRLCertificateIssuerChain := "-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAkCgAwIBAgIUWSPTp0qoY1QuOXCt4A8HK1ckKrcwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE5MTAzMTEyMzM0N1oXDTM0MTAzMTEyMzM0N1owcDEiMCAG%0AA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwg%0AQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEL%0AMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQwp%2BLc%2BTUBtg1H%0A%2BU8JIsMsbjHjCkTtXb8jPM6r2dhu9zIblhDZ7INfqt3Ix8XcFKD8k0NEXrkZ66qJ%0AXa1KzLIKo4G%2FMIG8MB8GA1UdIwQYMBaAFOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMFYG%0AA1UdHwRPME0wS6BJoEeGRWh0dHBzOi8vc2J4LWNlcnRpZmljYXRlcy50cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQU%0AWSPTp0qoY1QuOXCt4A8HK1ckKrcwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQI%0AMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1q%2BFTz%2BgUuVfBQuCgJsFrL2TTS%0Ae1aBZ53O52TjFie6AiAriPaRahUX9Oa9kGLlAchWXKT6j4RWSR50BqhrN3UT4A%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIClDCCAjmgAwIBAgIVAOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xOTEwMzEwOTQ5MjFaFw00OTEyMzEyMzU5NTlaMGgxGjAY%0ABgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3Jh%0AdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQG%0AEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE%2F6D%2F1WHNrWwPmNMIyBKMW5%0AJ6JzMsjo6xP2vkK1cdZGb1PGRP%2FC%2F8ECgiDkmklmzwLzLi%2B000m7LLrtKJA3oC2j%0Agb8wgbwwHwYDVR0jBBgwFoAU6ehEUlM2XEsYmhH8QxgspdwggEgwVgYDVR0fBE8w%0ATTBLoEmgR4ZFaHR0cHM6Ly9zYngtY2VydGlmaWNhdGVzLnRydXN0ZWRzZXJ2aWNl%0Acy5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuZGVyMB0GA1UdDgQWBBTp6ERSUzZc%0ASxiaEfxDGCyl3CCASDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH%2FBAgwBgEB%2FwIB%0AATAKBggqhkjOPQQDAgNJADBGAiEAzw9zdUiUHPMUd0C4mx41jlFZkrM3y5f1lgnV%0AO7FbjOoCIQCoGtUmT4cXt7V%2BySHbJ8Hob9AanpvXNH1ER%2B%2FgZF%2BopQ%3D%3D%0A-----END%20CERTIFICATE-----%0A"

	respHeader.Add("SGX-PCK-CRL-Issuer-Chain", SGXPCKCRLCertificateIssuerChain)

	return &http.Response{
		StatusCode: c.ResponseCode,
		Body:       ioutil.NopCloser(strings.NewReader(crlEnodedString)),
		Header:     respHeader,
	}, nil
}
