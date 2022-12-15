/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"intel/isecl/lib/common/v5/setup"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("port: 1337\nsvs:\n")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	assert.Equal(t, 1337, c.Port)
}

func TestSave(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	c.Save()
	c2 := Load(temp.Name())
	assert.Equal(t, 1337, c2.Port)

	// File not exist. File will be created and returned.
	c1 := Load("test.yaml")
	err := c1.Save()
	assert.Equal(t, err, nil)

	os.Remove(temp.Name())
	os.Remove("test.yaml")
}

func TestNoConfigFileErr(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Configuration{}
	c.Port = 1337
	err := c.Save()
	assert.True(t, strings.Contains(err.Error(), ErrNoConfigFile.Error()))
}

func TestSaveConfigurationCMSTlsUnset(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_TLS_CERT_SHA384 is not defined in environment"))
}

func TestSaveConfigurationCMSUrlInvalid(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	os.Setenv("CMS_BASE_URL", "invalidurl")
	defer os.Clearenv()
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_BASE_URL provided is invalid"))
}

func TestSaveConfigurationCMSUrlUnset(t *testing.T) {
	temp, _ := ioutil.TempFile(".", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	defer os.Clearenv()
	c.Port = 1337
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_BASE_URL is not defined in environment"))
}

func TestSaveConfigurationNegativeCases(t *testing.T) {
	temp, _ := ioutil.TempFile(".", "config.yml")
	defer os.Remove(temp.Name())

	c := Load(temp.Name())

	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	os.Setenv("CMS_BASE_URL", "https://cms.com/v1/cms/")
	defer os.Clearenv()
	c.Port = 1337
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.Equal(t, err, nil)

	os.Setenv("SIGN_QUOTE_RESPONSE", "true")
	defer os.Clearenv()
	err = c.SaveConfiguration("all", setupContext)
	assert.Equal(t, err, nil)

	os.Setenv("SIGN_QUOTE_RESPONSE", "testvalue")
	os.Setenv("USE_PSS_PADDING", "testValue")
	os.Setenv("RESPONSE_SIGNING_KEY_LENGTH", "15360")
	os.Setenv("SQVS_TLS_CERT_CN", "TEST COMMON NAME")
	os.Setenv("KEY_PATH", "/test/key/path")
	os.Setenv("CERT_PATH", "/test/cert/path")
	os.Setenv("SAN_LIST", "test.com")
	defer os.Clearenv()
	err = c.SaveConfiguration("all", setupContext)
	assert.Equal(t, err, nil)

	os.Setenv("RESPONSE_SIGNING_KEY_LENGTH", "4096")
	defer os.Clearenv()
	err = c.SaveConfiguration("all", setupContext)
	assert.Equal(t, err, nil)
}

func TestGlobal(t *testing.T) {
	c := Global()
	assert.NotEqual(t, c, nil)

	global = &Configuration{
		configFile: "testfile",
		Port:       1337,
	}
	c = Global()
	assert.NotEqual(t, c, nil)
}
