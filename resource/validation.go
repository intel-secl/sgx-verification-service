/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"regexp"
	"intel/isecl/svs/constants"
	log "github.com/sirupsen/logrus"
 )

var regExMap = map[string]*regexp.Regexp{
				constants.Fmspc_Key: regexp.MustCompile(`^[0-9a-fA-F]{12}$`),
                                constants.Misc_Select: regexp.MustCompile(`^[0-9a-fA-F]{8}$`),
                                constants.Misc_SelectMask: regexp.MustCompile(`^[0-9a-fA-F]{8}$`),
                                constants.Attributes: regexp.MustCompile(`^[0-9a-fA-F]{32}$`),
                                constants.Attributes_Mask: regexp.MustCompile(`^[0-9a-fA-F]{32}$`),
                                constants.Mrsigner_key: regexp.MustCompile(`^[0-9a-fA-F]{64}$`)}
 
func ValidateInputString(key string, inString string) bool {

	regEx := regExMap[key]
	if len(key)<=0 || !regEx.MatchString(inString) {
		log.WithField(key, inString).Error("Input Validation")
		return false
	}
	log.WithField(key, inString).Debug("Input Validation")
	return true
}

