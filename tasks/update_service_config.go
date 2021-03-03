/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/sqvs/v3/config"
	"intel/isecl/sqvs/v3/constants"
	"io"
	"io/ioutil"
	"os"
	"time"
)

type Update_Service_Config struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

var slog = commLog.GetSecurityLogger()

func (u Update_Service_Config) Run(c setup.Context) error {
	fmt.Fprintln(u.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SQVS_PORT", "sgx verification service http port")
	if err != nil {
		defaultPort = constants.DefaultHTTPSPort
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.IntVar(&u.Config.Port, "port", defaultPort, "sgx verification Service http port")
	err = fs.Parse(u.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/server:Run() Could not parse input flags")
	}

	if u.Config.Port > 65535 || u.Config.Port <= 1024 {
		return errors.Wrap(err, "tasks/server:Run() Invalid or reserved port")
	}
	fmt.Fprintf(u.ConsoleWriter, "Using HTTPS port: %d\n", u.Config.Port)

	readTimeout, err := c.GetenvInt("SQVS_SERVER_READ_TIMEOUT", "SGX Verification Service Read Timeout")
	if err != nil {
		u.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		u.Config.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("SQVS_SERVER_READ_HEADER_TIMEOUT", "SGX Verification Service Read Header Timeout")
	if err != nil {
		u.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		u.Config.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("SQVS_SERVER_WRITE_TIMEOUT", "SGX Verification Service Write Timeout")
	if err != nil {
		u.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		u.Config.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("SQVS_SERVER_IDLE_TIMEOUT", "SGX Verification Service Service Idle Timeout")
	if err != nil {
		u.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		u.Config.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("SQVS_SERVER_MAX_HEADER_BYTES", "SGX Verification Service Max Header Bytes Timeout")
	if err != nil {
		u.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		u.Config.MaxHeaderBytes = maxHeaderBytes
	}

	logLevel, err := c.GetenvString(constants.SQVSLogLevel, "SQVS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SQVSLogLevel)
		u.Config.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			u.Config.LogLevel = log.InfoLevel
		} else {
			u.Config.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	logMaxLen, err := c.GetenvInt("SQVS_LOG_MAX_LENGTH", "SGX Verification Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		u.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		u.Config.LogMaxLength = logMaxLen
	}

	u.Config.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString("SQVS_ENABLE_CONSOLE_LOG", "SGX Verification Service Enable standard output")
	if err != nil || len(logEnableStdout) == 0 {
		u.Config.LogEnableStdout = false
	} else {
		u.Config.LogEnableStdout = true
	}

	includeToken, err := c.GetenvString("SQVS_INCLUDE_TOKEN", "Boolean value to decide whether to use token based auth or no auth for quote verifier API")
	if err == nil && includeToken != "" {
		u.Config.IncludeToken = includeToken
	} else if u.Config.IncludeToken == "" {
		u.Config.IncludeToken = constants.DefaultIncludeTokenValue
	}

	scsBaseUrl, err := c.GetenvString("SCS_BASE_URL", "SGX Caching Service URL")
	if err == nil && scsBaseUrl != "" {
		u.Config.SCSBaseUrl = scsBaseUrl
	} else if u.Config.SCSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("SCS_BASE_URL is not defined in environment")
		return errors.Wrap(errors.New("SCS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasApiUrl, err := c.GetenvString("AAS_API_URL", "AAS API URL")
	if err == nil && aasApiUrl != "" {
		u.Config.AuthServiceUrl = aasApiUrl
	} else if u.Config.AuthServiceUrl == "" {
		commLog.GetDefaultLogger().Error("AAS_API_URL is not defined in environment")
		return errors.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	trustedRootPath, err := c.GetenvString("SGX_TRUSTED_ROOT_CA_PATH", "SQVS Trusted Root CA")
	if err == nil && trustedRootPath != "" {
		trustedRoot, err := ioutil.ReadFile(trustedRootPath)
		if err != nil {
			return errors.New("SaveConfiguration: Filed read error: " + trustedRootPath + " : " + err.Error())
		}
		block, _ := pem.Decode(trustedRoot)
		if block == nil {
			return errors.New("SaveConfiguration: Pem Decode error")
		}
		u.Config.TrustedRootCA, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("SaveConfiguration: ParseCertificate error: " + err.Error())
		}
	} else {
		if _, err := os.Stat(trustedRootPath); err != nil {
			return errors.Errorf("SaveConfiguration: Could not find file: %s", trustedRootPath)
		}
		return errors.New("SaveConfiguration: Invalid pem certificate")
	}

	err = u.Config.Save()
	if err != nil {
		return errors.Wrap(err, "failed to save SQVS config")
	}
	return nil
}

func (u Update_Service_Config) Validate(c setup.Context) error {
	return nil
}
