/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"crypto/x509"
	"errors"
	errorLog "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/sqvs/v3/constants"
	"os"
	"path"
	"time"
)

var slog = commLog.GetSecurityLogger()

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
type Configuration struct {
	configFile       string
	Port             int
	CmsTlsCertDigest string

	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        log.Level

	SQVS struct {
		User     string
		Password string
	}
	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	IncludeToken   string
	CMSBaseUrl     string
	AuthServiceUrl string
	SCSBaseUrl     string
	Subject        struct {
		TLSCertCommonName string
	}
	TrustedRootCA     *x509.Certificate
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

var global *Configuration

func Global() *Configuration {
	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	var err error

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	tlsCertCN, err := c.GetenvString("SQVS_TLS_CERT_CN", "SQVS TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultSQVSTlsCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	logLevel, err := c.GetenvString("SQVS_LOGLEVEL", "SQVS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SQVSLogLevel)
		conf.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			conf.LogLevel = log.InfoLevel
		} else {
			conf.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultSQVSTlsSan
	}

	return conf.Save()
}

func (c *Configuration) Save() error {
	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.OpenFile(c.configFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Failed to flush config.yml")
		}
	}()

	return yaml.NewEncoder(file).Encode(c)
}

func Load(filePath string) *Configuration {
	var c Configuration
	file, _ := os.Open(filePath)
	if file != nil {
		defer func() {
			derr := file.Close()
			if derr != nil {
				log.WithError(derr).Error("Failed to close config.yml")
			}
		}()
		err := yaml.NewDecoder(file).Decode(&c)
		if err != nil {
			log.WithError(err).Error("Failed to decode config.yml contents")
		}
	} else {
		c.LogLevel = log.InfoLevel
	}

	c.configFile = filePath
	return &c
}
