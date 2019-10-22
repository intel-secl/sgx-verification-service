/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

 package tasks

import (
        "testing"
        "os"
        "intel/isecl/svs/config"
        "intel/isecl/lib/common/setup"

        "github.com/stretchr/testify/assert"
)

func TestCreateCmsAuthToken(t *testing.T){
	assert := assert.New(t)
        os.Setenv("CMS_KEY_ALGORITHM", "RSA")
        os.Setenv("CMS_KEY_LENGTH", "3072")
	CreateSerialNumberFileAndJWTDir()
        c := config.Configuration{}

        at := Cms_Auth_Token{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: &c,
        }

        ctx := setup.Context{}
        err := createCmsAuthToken(at, ctx)
        assert.NoError(err)
        //defer os.RemoveAll("/etc/svs")
}


func TestAuthTokenRun(t *testing.T) {
        assert := assert.New(t)
        os.Setenv("CMS_KEY_ALGORITHM", "RSA")
        os.Setenv("CMS_KEY_LENGTH", "3072")
	CreateSerialNumberFileAndJWTDir()
        c := config.Configuration{}

        ca := Cms_Auth_Token{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: &c,
        }

        ctx := setup.Context{}
        err := ca.Run(ctx)
        assert.NoError(err)
}

