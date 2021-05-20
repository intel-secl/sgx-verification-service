/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v4/crypt"
	e "intel/isecl/lib/common/v4/exec"
	commLog "intel/isecl/lib/common/v4/log"
	commLogMsg "intel/isecl/lib/common/v4/log/message"
	commLogInt "intel/isecl/lib/common/v4/log/setup"
	"intel/isecl/lib/common/v4/middleware"
	cos "intel/isecl/lib/common/v4/os"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/sqvs/v4/config"
	"intel/isecl/sqvs/v4/constants"
	"intel/isecl/sqvs/v4/resource"
	"intel/isecl/sqvs/v4/tasks"
	"intel/isecl/sqvs/v4/version"
	"io"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
	SecLogWriter   io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sqvs <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Available Commands:")
	fmt.Fprintln(w, "    help|-h|--help		Show this help message")
	fmt.Fprintln(w, "    setup [task]		Run setup task")
	fmt.Fprintln(w, "    start			Start sqvs")
	fmt.Fprintln(w, "    status			Show the status of sqvs")
	fmt.Fprintln(w, "    stop			Stop sqvs")
	fmt.Fprintln(w, "    uninstall [--purge]	Uninstall SQVS. --purge option needs to be applied to remove configuration and data files")
	fmt.Fprintln(w, "    version|-v|--version	Show the version of sqvs")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Setup command usage:     sqvs setup [task] [--arguments=<argument_value>] [--force]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Available Tasks for setup:")
	fmt.Fprintln(w, "                              Required env variables:")
	fmt.Fprintln(w, "                                  - get required env variables from all the setup tasks")
	fmt.Fprintln(w, "                              Optional env variables:")
	fmt.Fprintln(w, "                                  - get optional env variables from all the setup tasks")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    update_service_config    Updates Service Configuration")
	fmt.Fprintln(w, "                             Required env variables:")
	fmt.Fprintln(w, "                                 - SQVS_PORT                                         : SGX Verification Service port")
	fmt.Fprintln(w, "                                 - SQVS_SERVER_READ_TIMEOUT                          : SGX Verification Service Read Timeout")
	fmt.Fprintln(w, "                                 - SQVS_SERVER_READ_HEADER_TIMEOUT                   : SGX Verification Service Read Header Timeout Duration")
	fmt.Fprintln(w, "                                 - SQVS_SERVER_WRITE_TIMEOUT                         : SGX Verification Service Request Write Timeout Duration")
	fmt.Fprintln(w, "                                 - SQVS_SERVER_IDLE_TIMEOUT                          : SGX Verification Service Request Idle Timeout")
	fmt.Fprintln(w, "                                 - SQVS_SERVER_MAX_HEADER_BYTES                      : SGX Verification Service Max Length Of Request Header Bytes")
	fmt.Fprintln(w, "                                 - SQVS_LOGLEVEL                                    : SGX Verification Service Log Level")
	fmt.Fprintln(w, "                                 - SQVS_LOG_MAX_LENGTH                               : SGX Verification Service Log maximum length")
	fmt.Fprintln(w, "                                 - SQVS_ENABLE_CONSOLE_LOG                           : SGX Verification Service Enable standard output")
	fmt.Fprintln(w, "                                 - SQVS_INCLUDE_TOKEN                                : Boolean value to decide whether to use token based auth or no auth for quote verifier API")
	fmt.Fprintln(w, "                                 - SGX_TRUSTED_ROOT_CA_PATH                          : SQVS Trusted Root CA")
	fmt.Fprintln(w, "                                 - SCS_BASE_URL                                      : SGX Caching Service URL")
	fmt.Fprintln(w, "                                 - AAS_API_URL                                       : AAS API URL")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_ca_cert         Download CMS root CA certificate")
	fmt.Fprintln(w, "                             - Option [--force] overwrites any existing files, and always downloads new root CA cert")
	fmt.Fprintln(w, "                             Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                                 - CMS_BASE_URL=<url>                                : for CMS API url")
	fmt.Fprintln(w, "                                 - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_cert TLS        Generates Key pair and CSR, gets it signed from CMS")
	fmt.Fprintln(w, "                             - Option [--force] overwrites any existing files, and always downloads newly signed TLS cert")
	fmt.Fprintln(w, "                             Required env variable if SQVS_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                                 - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                             Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                                 - CMS_BASE_URL=<url>               : for CMS API url")
	fmt.Fprintln(w, "                                 - BEARER_TOKEN=<token>             : for authenticating with CMS")
	fmt.Fprintln(w, "                                 - SAN_LIST=<san>                   : list of hosts which needs access to service")
	fmt.Fprintln(w, "                             Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                                - KEY_PATH=<key_path>              : Path of file where TLS key needs to be stored")
	fmt.Fprintln(w, "                                - CERT_PATH=<cert_path>            : Path of file/directory where TLS certificate needs to be stored")
	fmt.Fprintln(w, "    create_signing_key_pair  Generates Key pair and CSR and downloads Signing certificate from CMS")
	fmt.Fprintln(w, "                             - Option [--force] overwrites any existing files and always downloads new Signing cert")
	fmt.Fprintln(w, "                             Required env variable if SQVS_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                                 - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                             Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                                 - CMS_BASE_URL=<url>               : for CMS API url")
	fmt.Fprintln(w, "                                 - BEARER_TOKEN=<token>             : for authenticating with CMS")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	execPath, err := os.Executable()
	if err != nil {
		log.WithError(err).Error("app:executablePath() Unable to find SQVS executable")
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return execPath
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

func (a *App) configureLogs(stdOut, logFile bool) {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())

	f := commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, &f, ioWriterSecurity, false)

	slog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		fmt.Fprintf(os.Stderr, "Unrecognized command: %s\n", args[1])
		os.Exit(1)
	case "run":
		a.configureLogs(config.Global().LogEnableStdout, true)
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(5 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting SCS service")
		}
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "start":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.start()
	case "stop":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.stop()
	case "status":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		err := flag.CommandLine.Parse(args[2:])
		if err != nil {
			return err
		}
		a.uninstall(purge)
		log.Info("app:Run() Uninstalled SGX Verification Service")
		os.Exit(0)
	case "version", "--version", "-v":
		fmt.Println(version.GetVersion())
		return nil
	case "setup":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		var setupContext setup.Context
		if len(args) <= 2 {
			a.printUsage()
			os.Exit(1)
		}

		err := validateSetupArgs(args[2], args[3:])
		if err != nil {
			errMessage := "app:Run() Invalid setup task arguments"
			a.printUsage()
			return errors.Wrap(err, errMessage)
		}

		taskName := args[2]

		a.Config = config.Global()
		err = a.Config.SaveConfiguration(taskName, setupContext)
		if err != nil {
			fmt.Println("Error saving configuration: " + err.Error())
			os.Exit(1)
		}
		task := strings.ToLower(args[2])
		flags := args[3:]

		if args[2] == "download_cert" && len(args) > 3 {
			flags = args[4:]
		}

		a.Config = config.Global()
		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
					Flags:                args,
					CmsBaseURL:           a.Config.CMSBaseURL,
					CaCertDirPath:        constants.TrustedCAsStoreDir,
					TrustedTlsCertDigest: a.Config.CmsTLSCertDigest,
					ConsoleWriter:        os.Stdout,
				},
				setup.Download_Cert{
					Flags:              flags,
					KeyFile:            a.Config.TLSKeyFile,
					CertFile:           a.Config.TLSCertFile,
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
					CmsBaseURL:         a.Config.CMSBaseURL,
					Subject: pkix.Name{
						CommonName: a.Config.Subject.TLSCertCommonName,
					},
					SanList:       a.Config.CertSANList,
					CertType:      "TLS",
					CaCertsDir:    constants.TrustedCAsStoreDir,
					BearerToken:   "",
					ConsoleWriter: os.Stdout,
				},
				tasks.Update_Service_Config{
					Flags:                    flags,
					Config:                   a.configuration(),
					ConsoleWriter:            os.Stdout,
					TrustedSGXRootCAFilePath: constants.TrustedSGXRootCAFile,
				},
				tasks.Create_Signing_Key_Pair{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
			},
			AskInput: false,
		}
		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			log.WithError(err).Errorf("Setup task %s failed", task)
			return err
		}

		// Containers are always run as non root users, does not require changing ownership of config directories
		if _, err := os.Stat("/.container-env"); err == nil {
			return nil
		}

		sqvsUser, err := user.Lookup(constants.SQVSUserName)
		if err != nil {
			return errors.Wrapf(err, "Could not find user '%s'", constants.SQVSUserName)
		}

		uid, err := strconv.Atoi(sqvsUser.Uid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse sqvs user uid '%s'", sqvsUser.Uid)
		}

		gid, err := strconv.Atoi(sqvsUser.Gid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse sqvs user gid '%s'", sqvsUser.Gid)
		}

		// Change the file ownership to sqvs user
		err = cos.ChownR(constants.ConfigDir, uid, gid)
		if err != nil {
			return errors.Wrap(err, "Error while changing file ownership")
		}
		if task == "download_cert" {
			err = os.Chown(a.Config.TLSKeyFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Key file")
			}

			err = os.Chown(a.Config.TLSCertFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Cert file")
			}
		}
		if task == "create_signing_key_pair" {
			err = os.Chown(constants.PrivateKeyLocation, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Key file")
			}

			err = os.Chown(constants.PublicKeyLocation, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Cert file")
			}
		}
	}
	return nil
}

func (a *App) startServer() error {
	c := a.configuration()
	log.Info("Starting SGX Quote Verification Server")
	// Create Router, set routes
	r := mux.NewRouter()
	r.SkipClean(true)

	// set version endpoint
	sr := r.PathPrefix("/svs/v{version:[1-2]}/").Subrouter()
	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.SetVersionRoutes)

	sr = r.PathPrefix("/svs/v1/").Subrouter()
	if c.IncludeToken == true {
		sr.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, fnGetJwtCerts,
			time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	}

	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.QuoteVerifyCB)

	sr = r.PathPrefix("/svs/v2/").Subrouter()
	if c.IncludeToken == true {
		sr.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, fnGetJwtCerts,
			time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	}
	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.QuoteVerifyCBAndSign)

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.ReadTimeout,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    c.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		conf := config.Global()
		if conf != nil {
			tlsCert := conf.TLSCertFile
			tlsKey := conf.TLSKeyFile
			if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
				log.WithError(err).Info("Failed to start HTTPS server")
				stop <- syscall.SIGTERM
			}
		}
	}()

	slog.Info(commLogMsg.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	slog.Info(commLogMsg.ServiceStop)
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sqvs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:start() Could not locate systemctl to start application service")
	}
	cmd := exec.Command(systemctl, "start", "sqvs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sqvs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:stop() Could not locate systemctl to stop application service")
	}
	cmd := exec.Command(systemctl, "stop", "sqvs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sqvs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:status() Could not locate systemctl to check status of application service")
	}
	cmd := exec.Command(systemctl, "status", "sqvs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) uninstall(purge bool) {
	fmt.Println("Uninstalling sgx verification service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		log.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			log.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		log.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		log.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "sgx verification service uninstalled")
	err = a.stop()
	if err != nil {
		log.WithError(err).Error("error stopping service")
	}
}

func removeService() {
	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove sgx verification service")
		fmt.Println("Error : ", err)
	}
}

func validateSetupArgs(cmd string, args []string) error {
	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
		return nil

	case "update_service_config":
		return nil

	case "create_signing_key_pair":
		return nil

	case "all":
		if len(args) != 0 {
			return errors.New("Please setup the arguments with env")
		}
	}
	return nil
}

func fnGetJwtCerts() error {
	conf := config.Global()
	if conf == nil {
		return errors.New("failed to read config")
	}
	if !strings.HasSuffix(conf.AuthServiceURL, "/") {
		conf.AuthServiceURL += "/"
	}
	url := conf.AuthServiceURL + "jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCAsStoreDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "Could not read root CA certificate")
	}
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		log.Error("Failed to fetch JWT cert")
		return errors.Wrap(err, "Could not retrieve jwt certificate")
	}
	if res != nil {
		defer func() {
			derr := res.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing jwtcert response")
			}
		}()
	}

	body, _ := ioutil.ReadAll(res.Body)
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "Could not store Certificate")
	}

	return nil
}
