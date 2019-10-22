/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"io/ioutil"
	"os"
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
}
