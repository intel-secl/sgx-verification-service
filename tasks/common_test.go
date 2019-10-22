/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
        "os"
	"intel/isecl/svs/constants"
)

func CreateSerialNumberFileAndJWTDir(){
        os.MkdirAll(constants.ConfigDir, os.ModePerm)
        os.MkdirAll(constants.TrustedJWTSigningCertsDir, os.ModePerm)
	os.MkdirAll(constants.RootCADirPath, os.ModePerm)
        var file, _ = os.Create(constants.SerialNumberPath)
        defer file.Close()
}

