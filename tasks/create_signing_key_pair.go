/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"intel/isecl/lib/common/v5/crypt"
	commLog "intel/isecl/lib/common/v5/log"
	csetup "intel/isecl/lib/common/v5/setup"
	"intel/isecl/sqvs/v5/config"
	"intel/isecl/sqvs/v5/constants"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
	"os"
)

type Create_Signing_Key_Pair struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

var defaultLog = commLog.GetDefaultLogger()

// Validate method is used to check if the keyPair exists on disk
func (cskp Create_Signing_Key_Pair) Validate(c csetup.Context) error {
	defaultLog.Trace("tasks/create_encryption_key_pair: Validate() Entering")
	defer defaultLog.Trace("tasks/create_encryption_key_pair: Validate() Leaving")

	_, err := os.Stat(constants.PrivateKeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_encryption_key_pair: Validate() Private key does not exist")
	}

	priv, err := ioutil.ReadFile(constants.PrivateKeyLocation)
	if err != nil {
		return errors.Wrap(err, "error reading signing key from file")
	}
	privPem, _ := pem.Decode(priv)
	_, err = x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		return errors.Wrap(err, "Cannot parse RSA private key from file")
	}

	_, err = os.Stat(constants.PublicKeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_encryption_key_pair: Validate() Public key does not exist")
	}

	_, err = ioutil.ReadFile(constants.PublicKeyLocation)
	if err != nil {
		return errors.Wrap(err, "error reading signing certificate from file")
	}
	return nil
}

func (cskp Create_Signing_Key_Pair) Run(c csetup.Context) error {
	defaultLog.Trace("tasks/create_encryption_key_pair: Run() Entering")
	defer defaultLog.Trace("tasks/create_encryption_key_pair: Run() Leaving")

	conf := config.Global()

	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing key-pair Keys")

	err := fs.Parse(cskp.Flags)
	if err != nil {
		fmt.Fprintln(cskp.ConsoleWriter, "CA certificate setup: Unable to parse flags")
		return fmt.Errorf("tasks/create_encryption_keypair: Run() CA certificate setup: Unable to parse flags")
	}

	if *force || cskp.Validate(c) != nil {
		defaultLog.Info("tasks/create_encryption_key_pair: Run() Creating key-pair")

		bearerToken, err := c.GetenvSecret("BEARER_TOKEN", "bearer token")
		if err != nil || bearerToken == "" {
			fmt.Fprintln(cskp.ConsoleWriter, "BEARER_TOKEN not found in environment for downloading certificate")
			return errors.New("Certificate setup: BEARER_TOKEN not found in environment for downloading certificate")
		}

		key, cert, err := csetup.GetCertificateFromCMS("Signing", constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength,
			conf.CMSBaseURL, pkix.Name{CommonName: constants.DefaultSQVSSigningCertCn}, "",
			constants.TrustedCAsStoreDir, bearerToken)
		if err != nil {
			fmt.Fprintln(cskp.ConsoleWriter, "Error getting signing certificate ")
			return fmt.Errorf("Certificate setup: %v", err)
		}

		err = crypt.SavePrivateKeyAsPKCS8(key, constants.PrivateKeyLocation)
		if err != nil {
			fmt.Fprintln(cskp.ConsoleWriter, "Error storing private key to file")
			return fmt.Errorf("Certificate setup: %v", err)
		}

		err = ioutil.WriteFile(constants.PublicKeyLocation, cert, 0644)
		if err != nil {
			fmt.Fprintln(cskp.ConsoleWriter, "Could not store Certificate")
			return fmt.Errorf("Certificate setup: %v", err)
		}
		if err = os.Chmod(constants.PublicKeyLocation, 0644); err != nil {
			fmt.Fprintln(cskp.ConsoleWriter, "Could not store Certificate")
			return fmt.Errorf("Certificate setup: %v", err)
		}
	} else {
		fmt.Fprintln(cskp.ConsoleWriter, "Signing Certificate already downloaded, skipping")
	}
	fmt.Fprintln(cskp.ConsoleWriter, "Quote Signing Key Pair Created")
	return nil
}
