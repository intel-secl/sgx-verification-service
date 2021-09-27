/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/pem"
	"flag"
	"fmt"
	commLog "intel/isecl/lib/common/v5/log"
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/constants"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Update_Service_Config struct {
	Flags                    []string
	Config                   *config.Configuration
	ConsoleWriter            io.Writer
	TrustedSGXRootCAFilePath string
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

	readTimeout, err := c.GetenvString("SQVS_SERVER_READ_TIMEOUT", "SGX Verification Service Read Timeout")
	if err != nil {
		u.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		u.Config.ReadTimeout, err = time.ParseDuration(readTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SQVS_SERVER_READ_TIMEOUT setting it to the default value\n")
			u.Config.ReadTimeout = constants.DefaultReadTimeout
		}
	}

	readHeaderTimeout, err := c.GetenvString("SQVS_SERVER_READ_HEADER_TIMEOUT", "SGX Verification Service Read Header Timeout")
	if err != nil {
		u.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		u.Config.ReadHeaderTimeout, err = time.ParseDuration(readHeaderTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SQVS_SERVER_READ_HEADER_TIMEOUT setting it to the default value\n")
			u.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
		}
	}

	writeTimeout, err := c.GetenvString("SQVS_SERVER_WRITE_TIMEOUT", "SGX Verification Service Write Timeout")
	if err != nil {
		u.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		u.Config.WriteTimeout, err = time.ParseDuration(writeTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SQVS_SERVER_WRITE_TIMEOUT setting it to the default value\n")
			u.Config.WriteTimeout = constants.DefaultWriteTimeout
		}
	}

	idleTimeout, err := c.GetenvString("SQVS_SERVER_IDLE_TIMEOUT", "SGX Verification Service Service Idle Timeout")
	if err != nil {
		u.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		u.Config.IdleTimeout, err = time.ParseDuration(idleTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SQVS_SERVER_IDLE_TIMEOUT setting it to the default value\n")
			u.Config.IdleTimeout = constants.DefaultIdleTimeout
		}
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

	includeToken, err := c.GetenvString("SQVS_INCLUDE_TOKEN", "Boolean value to decide whether to use "+
		"token based auth or no auth for quote verifier API")
	if err == nil && includeToken != "" {
		u.Config.IncludeToken, err = strconv.ParseBool(includeToken)
		if err != nil {
			u.Config.IncludeToken = constants.DefaultIncludeTokenValue
		}
	}

	scsBaseUrl, err := c.GetenvString("SCS_BASE_URL", "SGX Caching Service URL")
	if err == nil && scsBaseUrl != "" {
		if _, err = url.ParseRequestURI(scsBaseUrl); err != nil {
			return errors.Wrap(err, "SaveConfiguration() SCS_BASE_URL provided is invalid")
		}
		u.Config.SCSBaseURL = scsBaseUrl
	} else if u.Config.SCSBaseURL == "" {
		commLog.GetDefaultLogger().Error("SCS_BASE_URL is not defined in environment")
		return errors.Wrap(errors.New("SCS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasApiUrl, err := c.GetenvString("AAS_API_URL", "AAS API URL")
	if err == nil && aasApiUrl != "" {
		if _, err = url.ParseRequestURI(aasApiUrl); err != nil {
			return errors.Wrap(err, "SaveConfiguration() AAS_API_URL provided is invalid")
		}
		u.Config.AuthServiceURL = aasApiUrl
	} else if u.Config.AuthServiceURL == "" {
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
		err = ioutil.WriteFile(u.TrustedSGXRootCAFilePath, trustedRoot, 0640)
		if err != nil {
			return errors.New("SaveConfiguration: Error writing SGX root cert to file: " + err.Error())
		}
	} else {
		if _, err := os.Stat(trustedRootPath); err != nil {
			return errors.Errorf("SaveConfiguration: Could not find file: %s", trustedRootPath)
		}
		return errors.New("SaveConfiguration: Invalid pem certificate")
	}

	signQuoteResponse, err := c.GetenvString("SIGN_QUOTE_RESPONSE", "Enable Quote "+
		"Response Signing")
	if err == nil && strings.TrimSpace(signQuoteResponse) != "" {
		u.Config.SignQuoteResponse, err = strconv.ParseBool(signQuoteResponse)
		if err != nil {
			log.Warning("SIGN_QUOTE_RESPONSE is not defined properly, must be true/false. Quote Signing" +
				"will be skipped by default")
			u.Config.SignQuoteResponse = false
		}
	} else {
		u.Config.SignQuoteResponse = false
	}

	usePSSPadding, err := c.GetenvString("USE_PSS_PADDING", "Enable PSS padding")
	if err == nil && strings.TrimSpace(usePSSPadding) != "" {
		u.Config.UsePSSPadding, err = strconv.ParseBool(usePSSPadding)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "USE_PSS_PADDING is not defined properly, must be true/false. PKCS1V1.5 padding will be used\n")
			u.Config.UsePSSPadding = false
		}
	} else {
		u.Config.UsePSSPadding = false
	}

	u.Config.ResponseSigningKeyLength, err = c.GetenvInt("RESPONSE_SIGNING_KEY_LENGTH", "Response signing key length")
	if err == nil {
		switch u.Config.ResponseSigningKeyLength {
		case 2048, 3072:
		default:
			fmt.Fprintf(u.ConsoleWriter, "Response Signing Key Length must be 2048 or 3072. 3072 will be used by default.\n")
			u.Config.ResponseSigningKeyLength = constants.DefaultKeyAlgorithmLength
		}
	} else {
		u.Config.ResponseSigningKeyLength = constants.DefaultKeyAlgorithmLength
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
