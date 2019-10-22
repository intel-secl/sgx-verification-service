/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/svs/constants"
	"os"
	"path"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File) {
	logFilePath := path.Join(constants.LogDir, constants.LogFile)
	logFile, _ = os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(logFilePath, 0664)
	httpLogFilePath := path.Join(constants.LogDir, constants.HTTPLogFile)
	httpLogFile, _ = os.OpenFile(httpLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(httpLogFilePath, 0664)
	return
}

func main() {
	l, h := openLogFiles()
	defer l.Close()
	defer h.Close()
	app := &App{
		LogWriter:     l,
		HTTPLogWriter: h,
	}

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
