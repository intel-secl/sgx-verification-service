/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"fmt"
	"os"
	"path"
	"sync"
	"errors"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"strconv"

	"intel/isecl/svs/constants"
	"intel/isecl/lib/common/setup"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// should move this into lib common, as its duplicated across TDS and TDA

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	LogLevel         log.Level

	CACertValidity         int
	Organization           string
	Locality               string
	Province               string
	Country                string
	KeyAlgorithm           string
	KeyAlgorithmLength     int
	RootCACertDigest       string
	TokenDurationMins      int

	AasJwtCn               string
	AasTlsCn               string
	AasTlsSan              string

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}

	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseUrl string
	SCSBaseUrl string
	Subject struct {
		TLSCertCommonName string
		JWTCertCommonName string
		Organization      string
		Country           string
		Province          string
		Locality          string
	}
        ProvServerInfo struct {
                CachingServerUrl   string
                ApiSubscriptionkey string
        }

	TrustedRootCA		*x509.Certificate
        ProxyUrl 		string
	ProxyEnable             string
	AuthServiceUrl         	string
}

var mu sync.Mutex

var global *Configuration

func Global() *Configuration {
	log.Trace("config/config:Global() Entering")
	defer log.Trace("config/config:Global() Leaving")

	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

        var err error = nil
        
	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
        if err == nil && cmsBaseUrl != "" {
                conf.CMSBaseUrl = cmsBaseUrl
        } else if conf.CMSBaseUrl == "" {
                    log.Error("CMS_BASE_URL is not defined in environment")
        }

	proxyUrl, err := c.GetenvString("PROXY_URL", "Enviroment Proxy URL")
	if err == nil  && proxyUrl != ""{
		conf.ProxyUrl = proxyUrl
	} else if conf.ProxyUrl == "" {
		log.Error("PROXY_URL is not defined in environment")
	}

	scsBaseUrl, err := c.GetenvString("SCS_BASE_URL", "SGX Caching Service URL")
	if err == nil && scsBaseUrl != "" {
		conf.SCSBaseUrl = scsBaseUrl
	} else if conf.SCSBaseUrl == "" {
		return errors.New("SaveConfiguration: Invalid SCS Base URL certificate")
	}

	setProxy, err := c.GetenvString("PROXY_ENABLE", "Set Proxy Enable/Disable")
	if err == nil && setProxy != "" {
		conf.ProxyEnable = setProxy
	} else if conf.ProxyEnable == "" {
		conf.ProxyEnable = strconv.FormatBool(constants.ProxyDisable)
	}
        
	jwtCertCN, err := c.GetenvString("SVS_JWT_CERT_CN", "SVS JWT Certificate Common Name")
        if err == nil && jwtCertCN != "" {
                conf.Subject.JWTCertCommonName = jwtCertCN
        } else if conf.Subject.JWTCertCommonName == "" {
                conf.Subject.JWTCertCommonName = constants.DefaultSvsJwtCn
        }

        tlsCertCN, err := c.GetenvString("SVS_TLS_CERT_CN", "SVS TLS Certificate Common Name")
        if err == nil && tlsCertCN != "" {
                conf.Subject.TLSCertCommonName = tlsCertCN
        } else if conf.Subject.TLSCertCommonName == "" {
                conf.Subject.TLSCertCommonName = constants.DefaultSvsTlsCn
        }

        certOrg, err := c.GetenvString("SVS_CERT_ORG", "SVS Certificate Organization")
        if err == nil && certOrg != "" {
                conf.Subject.Organization = certOrg
        } else if conf.Subject.Organization == "" {
                conf.Subject.Organization = constants.DefaultSvsCertOrganization
        }

        certCountry, err := c.GetenvString("SVS_CERT_COUNTRY", "SVS Certificate Country")
        if err == nil &&  certCountry != "" {
                conf.Subject.Country = certCountry
        } else if conf.Subject.Country == "" {
                conf.Subject.Country = constants.DefaultSvsCertCountry
        }

        certProvince, err := c.GetenvString("SVS_CERT_PROVINCE", "SVS Certificate Province")
        if err == nil && certProvince != "" {
                conf.Subject.Province = certProvince
        } else if err != nil || conf.Subject.Province == "" {
                conf.Subject.Province = constants.DefaultSvsCertProvince
        }
        certLocality, err := c.GetenvString("SVS_CERT_LOCALITY", "SVS Certificate Locality")
        if err == nil && certLocality != "" {
                conf.Subject.Locality = certLocality
        } else if conf.Subject.Locality == "" {
                conf.Subject.Locality = constants.DefaultSvsCertLocality
        }


       	trustedRootPath, err := c.GetenvString("SGX_TRUSTED_ROOT_CA_PATH", "SVS SGX Trusted Root ca")
        if err == nil && trustedRootPath != "" {
		fmt.Println("Trusted CA pem:%s\n", trustedRootPath)
		trustedRoot, err := ioutil.ReadFile(trustedRootPath)
		if err != nil {
			return errors.New("SaveConfiguration: Filed read error: " + trustedRootPath +  " : "+ err.Error())
		}

		block, _ := pem.Decode([]byte(trustedRoot))
		if block == nil {
			return errors.New("SaveConfiguration: Pem Decode error")
		}
		conf.TrustedRootCA, err =  x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("SaveConfiguration: ParseCertificate error: "+ err.Error())
		}
        } else {
		return errors.New("SaveConfiguration: Invalid pem certificate")
	}

        return conf.Save()

}

func (c *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func Load(path string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.ErrorLevel
	}

	c.LogLevel = log.InfoLevel
	c.configFile = path
	return &c
}
