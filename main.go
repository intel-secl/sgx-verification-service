/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"intel/isecl/sqvs/v3/constants"
	_ "intel/isecl/sqvs/v3/swagger/docs"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile, httpLogFile, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.LogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.HTTPLogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	secLogFile, err = os.OpenFile(constants.SecLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.SecLogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	// Containers are always run as non root users, does not require changing ownership of config directories
	if _, err := os.Stat("/.container-env"); err == nil {
		return logFile, httpLogFile, secLogFile, nil
	}

	sqvsUser, err := user.Lookup(constants.SQVSUserName)
	if err != nil {
		log.Errorf("Could not find user '%s'", constants.SQVSUserName)
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(sqvsUser.Uid)
	if err != nil {
		log.Errorf("Could not parse sqvs user uid '%s'", sqvsUser.Uid)
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(sqvsUser.Gid)
	if err != nil {
		log.Errorf("Could not parse sqvs user gid '%s'", sqvsUser.Gid)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.HTTPLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.SecLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.SecLogFile)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.LogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
		return nil, nil, nil, err
	}

	return
}

func main() {
	l, h, s, err := openLogFiles()
	var app *App
	if err != nil {
		app = &App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			closeLogFiles(l, h, s)
		}()
		app = &App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}
	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error: ", err.Error())
		closeLogFiles(l, h, s)
		os.Exit(1)
	}
}

func closeLogFiles(logFile, httpLogFile, secLogFile *os.File) {
	var err error
	err = logFile.Close()
	if err != nil {
		fmt.Println("Failed to close default log file:", err.Error())
	}
	err = httpLogFile.Close()
	if err != nil {
		fmt.Println("Failed to close http log file:", err.Error())
	}
	err = secLogFile.Close()
	if err != nil {
		fmt.Println("Failed to close security log file:", err.Error())
	}
}
