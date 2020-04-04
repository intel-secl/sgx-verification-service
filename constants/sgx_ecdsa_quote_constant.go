/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	SgxReportBodyReserved1Bytes	= 12
	SgxReportBodyReserved2Bytes	= 32
	SgxReportBodyReserved3Bytes	= 32
	SgxReportBodyReserved4Bytes	= 42
	SgxIsvextProdIdSize		= 16
	SgxIsvFamilyIdSize		= 16
	SgxReportDataSize		= 64
	SgxEpidGroupIdsize		= 4
	SgxBaseNamesize			= 32
	SgxConfigIdSize			= 64
	SgxCpusvnSize			= 16
	SgxHashSize			= 32
	QuoteReservedBytes		= 4
	QuoteHeaderUuidSize		= 16
	QuoteHeaderUserDataSize		= 20
	QuoteReserved1Bytes		= 28
	QuoteReserved2Bytes		= 32
	QuoteReserved3Bytes		= 96
	QuoteReserved4Bytes		= 60
	QuoteEnclaveReportCpuSvnSize	= 16
	QuoteEnclaveReportAttributesSize= 16
	QuoteEnclaveReportMrEnclaveSize	= 32
	QuoteEnclaveReportMrSignerSize	= 32
	QuoteEnclaveReportDataSize	= 64
	QuoteEcdsa256BitSignatureSize	= 64
	QuoteEcdsa256BitPubkeySize	= 64
)
