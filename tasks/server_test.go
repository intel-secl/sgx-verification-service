/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/setup"
	"intel/isecl/svs/config"
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestServerSetup(t *testing.T) {
	c := config.Configuration{}
	s := Server{
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
	os.Setenv("SVS_PORT", "12000")
	c := config.Configuration{}
	s := Server{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Equal(t, config.ErrNoConfigFile, err)
	assert.Equal(t, 12000, c.Port)
}
