/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	HomeDir                       = "/opt/svs/"
	ConfigDir                     = "/etc/svs/"
	ExecutableDir                 = "/opt/svs/bin/"
	ExecLinkPath                  = "/usr/bin/svs"
	RunDirPath                    = "/run/svs"
	LogDir                        = "/var/log/svs/"
	LogFile                       = "svs.log"
	HTTPLogFile                   = "http.log"
	ConfigFile                    = "config.yml"
	TokenKeyFile                  = "svs-jwt-key.pem"
	TLSKeyFile		      = "key.pem"
	TLSCertFile		      = "cert.pem"
	RootCADirPath                 = ConfigDir + "certs/trustedca/"
        //RootCACertPath                = RootCADirPath + "root-ca-cert.pem"
        RootCAKeyPath                 = ConfigDir + "root-ca-key.pem"
        TLSCertPath                   = ConfigDir + "tls-cert.pem"
        TLSKeyPath                    = ConfigDir + "tls-key.pem"
	SerialNumberPath              = ConfigDir + "serial-number"
	TokenSignKeysAndCertDir       = ConfigDir + "certs/tokensign/"
        TokenSignKeyFile              = TokenSignKeysAndCertDir + "jwt.key"
        TokenSignCertFile             = TokenSignKeysAndCertDir + "jwtsigncert.pem"
        TrustedJWTSigningCertsDir     = ConfigDir + "certs/trustedjwt/"
        TrustedCAsStoreDir            = ConfigDir + "certs/trustedca/"
        PIDFile                       = "svs.pid"
        ServiceRemoveCmd              = "systemctl disable svs"
        HashingAlgorithm              = crypto.SHA384
        PasswordRandomLength          = 20
        DefaultAuthDefendMaxAttempts  = 5
        DefaultAuthDefendIntervalMins = 5
        DefaultAuthDefendLockoutMins  = 15
        DefaultDBRotationMaxRowCnt    = 100000
        DefaultDBRotationMaxTableCnt  = 10
        DefaultSSLCertFilePath        = ConfigDir + "aasdbcert.pem"
        ServiceName                   = "SVS"
        DefaultHttpPort               = 8445
        DefaultKeyAlgorithm           = "rsa"
        DefaultKeyAlgorithmLength     = 3072
        DefaultAasTlsSan              = "127.0.0.1,localhost"
        DefaultSvsTlsCn               = "SVS TLS Certificate"
        DefaultSvsJwtCn               = "SVS JWT Signing Certificate"
	CertApproverGroupName         = "CertApprover"
	DefaultSvsCertProvince        = "SF"
        DefaultSvsCertLocality        = "SC"
        DefaultCACertValidiy          = 5
	DefaultRootCACommonName       = "SVSCA"
        DefaultPort                   = 8445
        DefaultSvsCertOrganization    = "INTEL"
        DefaultSvsCertCountry         = "US"
	DefaultTokenDurationMins      = 240
	DefaultIntelProvServerURL     = "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/"
	Fmspc_Key                     = "fmspc"
	Misc_Select                   = "miscselect"
	Misc_SelectMask               = "miscselectMask"
	Attributes                    = "attributes"
	Attributes_Mask               = "attributesMask"
	Mrsigner_key                  = "mrsigner"
	SGXRootCACertSubjectStr	      = "CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXInterCACertSubjectStr      = "CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US|CN=Intel SGX PCK Platform CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXCRLIssuerStr		      = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Processor CA|C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA"
	SGXPCKCertificateSubjectStr   = "CN=Intel SGX PCK Certificate,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXTCBInfoSubjectStr	      = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXQEInfoSubjectStr	      = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"	
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
	ProxyEnable   = true
	ProxyDisable  = false
)
const (
        // privileges granted: GET_ANY_HOST, DELETE_ANY_HOST, QUERY_REPORT, VERSION, CREATE_HOST
        AdminGroupName = "Administrators"

        // privileges granted: CREATE_HOST
        RegisterHostGroupName = "RegisterHosts"

        // privileges granted: GET_HOST, POST_REPORT
        HostSelfUpdateGroupName = "HostSelfUpdate"

        RoleAndUserManagerGroupName = "RoleAndUserManager"

        RoleManagerGroupName = "RoleManager"

        UserManagerGroupName = "UserManager"

        UserRoleManagerGroupName = "UserRoleManager"
)

func GetDefaultAdministratorRoles() []string {
        return []string{"RoleManager", "UserManager", "UserRoleManager"}
}
