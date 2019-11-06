/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/log"
	"io"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

var log = commLog.GetDefaultLogger()

func (s Server) Run(c setup.Context) error {
	log.Trace("tasks/server:Run() Entering")
	defer log.Trace("tasks/server:Run() Leaving")

	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SVS_PORT", "sgx serification service http port")
	if err != nil {
		defaultPort = constants.DefaultPort
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.IntVar(&s.Config.Port, "port", defaultPort, "sgx verification Service http port")
	err = fs.Parse(s.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/server:Run() Could not parse input flags")
	}

	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.Wrap(err, "tasks/server:Run() Invalid or reserved port")
        }
        fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

        s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
        s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
        s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins

        authServiceUrl, err := c.GetenvString("AAS_BASE_URL", "AuthService URL")
        if err != nil {
                authServiceUrl = ""
        }
        s.Config.AuthServiceUrl = authServiceUrl
        
	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
        if err != nil {
                cmsBaseUrl = ""
        }
        s.Config.CMSBaseUrl = cmsBaseUrl

        proxyUrl, err := c.GetenvString("PROXY_URL", "Enviroment Proxy URL")
        if err != nil {
                proxyUrl = ""
                fmt.Fprintf(s.ConsoleWriter, "Proxy URL not provided\n")
        }
        s.Config.ProxyUrl = proxyUrl


        return s.Config.Save()
}

func (s Server) Validate(c setup.Context) error {
	log.Trace("tasks/server:Validate() Entering")
	defer log.Trace("tasks/server:Validate() Leaving")

        return nil
}

