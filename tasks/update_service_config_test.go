/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/sqvs/v3/config"
	"os"
	"testing"
)

func TestServerSetup(t *testing.T) {
	c := config.Configuration{}
	s := Update_Service_Config{
		Flags:         []string{"-port=12000"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Equal(t, config.ErrNoConfigFile, err)
	assert.Equal(t, 12000, c.Port)
}

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("SQVS_PORT", "12000")
	c := config.Configuration{}
	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Equal(t, config.ErrNoConfigFile, err)
	assert.Equal(t, 12000, c.Port)
}
