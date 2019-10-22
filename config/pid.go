/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// Need to move these to lib common
// CheckPidFile checks if /var/run/cms/cms.pid exists
func CheckPidFile(path string) (pid int, err error) {
	pidData, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithError(err).Debug("Failed to read pidfile")
		return 0, err
	}
	pid, err = strconv.Atoi(string(pidData))
	if err != nil {
		log.WithError(err).WithField("pid", pidData).Debug("Failed to convert pidData string to int")
		return 0, err
	}
	return pid, nil
}

// WritePidFile writes the specified pid to /var/run/cms/cms.pid,
// creating it if it doesnt exist
func WritePidFile(path string, pid int) error {
	log.WithField("pid", pid).Debug("writing pid file")
	pidFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to write pid file: %v", err)
	}
	defer pidFile.Close()
	pidFile.WriteString(strconv.Itoa(pid))
	return nil
}
