/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"time"
)

const (
	HomeDir                        = "/opt/sqvs/"
	ConfigDir                      = "/etc/sqvs/"
	ExecLinkPath                   = "/usr/bin/sqvs"
	RunDirPath                     = "/run/sqvs"
	LogDir                         = "/var/log/sqvs/"
	LogFile                        = LogDir + "sqvs.log"
	SecLogFile                     = LogDir + "sqvs-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd               = "systemctl disable sqvs"
	ServiceName                    = "SQVS"
	ExplicitServiceName            = "SGX Quote Verification Service"
	QuoteVerifierGroupName         = "QuoteVerifier"
	SQVSUserName                   = "sqvs"
	DefaultHTTPSPort               = 12000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSQVSTLSSan              = "127.0.0.1,localhost"
	DefaultSQVSTLSCn               = "SQVS TLS Certificate"
	DefaultJwtValidateCacheKeyMins = 60
	CMSTLSCertDigestEnv            = "CMS_TLS_CERT_SHA384"
	SQVSLogLevel                   = "SQVS_LOGLEVEL"
	DefaultIncludeTokenValue       = "true"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 1 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
	SGXRootCACertSubjectStr        = "CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXInterCACertSubjectStr       = "CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US|CN=Intel SGX PCK Platform CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXCRLIssuerStr                = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Processor CA|C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA"
	SGXPCKCertificateSubjectStr    = "CN=Intel SGX PCK Certificate,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXTCBInfoSubjectStr           = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXQEInfoSubjectStr            = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	MaxTcbLevels                   = 16
	MaxTCBCompLevels               = 18
	FmspcLen                       = 12
	PCKCertType                    = 5
)
