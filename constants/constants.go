/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	"time"
)

const (
	HomeDir                        = "/opt/svs/"
	ConfigDir                      = "/etc/svs/"
	ExecutableDir                  = "/opt/svs/bin/"
	ExecLinkPath                   = "/usr/bin/svs"
	RunDirPath                     = "/run/svs"
	LogDir                         = "/var/log/svs/"
	LogFile                        = LogDir + "svs.log"
	SecLogFile                     = LogDir + "svs-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd               = "systemctl disable svs"
	HashingAlgorithm               = crypto.SHA384
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	ServiceName                    = "SVS"
	QuoteVerifierGroupName         = "QuoteVerifier"
	SVSUserName                    = "svs"
	DefaultHttpPort                = 12000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSvsTlsSan               = "127.0.0.1,localhost"
	DefaultSvsTlsCn                = "SVS TLS Certificate"
	DefaultIntelProvServerURL      = "https://api.trustedservices.intel.com/sgx/certification/v2/"
	DefaultJwtValidateCacheKeyMins = 60
	CmsTlsCertDigestEnv            = "CMS_TLS_CERT_SHA384"
	SVSLogLevel                    = "SVS_LOGLEVEL"
	SVS_USER                       = "SVS_USERNAME"
	SVS_PASSWORD                   = "SVS_PASSWORD"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
	Fmspc_Key                      = "fmspc"
	Misc_Select                    = "miscselect"
	Misc_SelectMask                = "miscselectMask"
	Attributes                     = "attributes"
	Attributes_Mask                = "attributesMask"
	Mrsigner_key                   = "mrsigner"
	SGXRootCACertSubjectStr        = "CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXInterCACertSubjectStr       = "CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US|CN=Intel SGX PCK Platform CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXCRLIssuerStr                = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Processor CA|C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA"
	SGXPCKCertificateSubjectStr    = "CN=Intel SGX PCK Certificate,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXTCBInfoSubjectStr           = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXQEInfoSubjectStr            = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	MaxTcbLevels                   = 16
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running      State = true
	ProxyEnable        = true
	ProxyDisable       = false
)
