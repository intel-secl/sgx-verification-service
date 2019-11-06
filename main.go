/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/svs/constants"
	"os"
)

func openLogFiles() (httpLogFile *os.File) {
	log.Trace("main:openLogFiles() Entering")
	defer log.Trace("main:openLogFiles() Leaving")

        httpLogFile, err := os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0755)
        if err != nil {
                log.Errorf("Could not open HTTP log file" + err.Error())
                return nil
        }
        os.Chmod(constants.HTTPLogFile, 0664)
        return httpLogFile
}

func main() {
        log.Trace("main:main() Entering")
        defer log.Trace("main:main() Leaving")

        h := openLogFiles()
        defer h.Close()
        app := &App{
                HTTPLogWriter: h,
        }
        err := app.Run(os.Args)
        if err != nil {
                log.WithError(err).Error("main:main() sgx-verification-service application error")
                log.Tracef("%+v",err)
                os.Exit(1)
        }
}
