/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/sqvs/constants"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.LogFile, 0664)

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.HTTPLogFile, 0664)

	secLogFile, err = os.OpenFile(constants.SecLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.SecLogFile, 0664)

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
		defer l.Close()
		defer h.Close()
		defer s.Close()
		app = &App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}
	err = app.Run(os.Args)
	if err != nil {
		log.Error("Application returned with error: ", err)
		os.Exit(1)
	}
}
