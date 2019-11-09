/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"path"
	stdlog "log"

	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	"intel/isecl/svs/resource"
	"intel/isecl/svs/tasks"
	"intel/isecl/svs/version"
	"intel/isecl/lib/common/proc"
	e "intel/isecl/lib/common/exec"
	cos "intel/isecl/lib/common/os"
	commLog "intel/isecl/lib/common/log"
	commLogInt "intel/isecl/lib/common/log/setup"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
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
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    svs <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    help|-h|-help    Show this help message")
	fmt.Fprintln(w, "    setup [task]     Run setup task")
	fmt.Fprintln(w, "    start            Start svs")
	fmt.Fprintln(w, "    status           Show the status of svs")
	fmt.Fprintln(w, "    stop             Stop svs")
	fmt.Fprintln(w, "    tlscertsha384    Show the SHA384 of the certificate used for TLS")
	fmt.Fprintln(w, "    uninstall        Uninstall svs")
	fmt.Fprintln(w, "    version          Show the version of svs")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Tasks for setup:")
        fmt.Fprintln(w, "    svs setup server [--port=<port>]")
        fmt.Fprintln(w, "        - Setup http server on <port>")
        fmt.Fprintln(w, "        - Environment variable SVS_PORT=<port> can be set alternatively")
        fmt.Fprintln(w, "    svs setup tls [--force] [--host_names=<host_names>]")
        fmt.Fprintln(w, "        - Use the key and certificate provided in /etc/threat-detection if files exist")
        fmt.Fprintln(w, "        - Otherwise create its own self-signed TLS keypair in /etc/svs for quality of life")
        fmt.Fprintln(w, "        - Option [--force] overwrites any existing files, and always generate self-signed keypair")
        fmt.Fprintln(w, "        - Argument <host_names> is a list of host names used by local machine, seperated by comma")
        fmt.Fprintln(w, "        - Environment variable SVS_TLS_HOST_NAMES=<host_names> can be set alternatively")
        fmt.Fprintln(w, "    svs setup admin [--user=<username>] [--pass=<password>]")
        fmt.Fprintln(w, "        - Environment variable SVS_ADMIN_USERNAME=<username> can be set alternatively")
        fmt.Fprintln(w, "        - Environment variable SVS_ADMIN_PASSWORD=<password> can be set alternatively")
        fmt.Fprintln(w, "    svs setup reghost [--user=<username>] [--pass=<password>]")
        fmt.Fprintln(w, "        - Environment variable SVS_REG_HOST_USERNAME=<username> can be set alternatively")
        fmt.Fprintln(w, "        - Environment variable SVS_REG_HOST_PASSWORD=<password> can be set alternatively")
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
	exec, err := os.Executable()
	if err != nil {
		log.WithError(err).Error("app:executablePath() Unable to find SVS executable")
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
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

var secLogFile *os.File
var defaultLogFile *os.File

func (a *App) configureLogs(isStdOut bool, isFileOut bool) {
        var ioWriterDefault io.Writer
        ioWriterDefault = defaultLogFile
        if isStdOut && isFileOut {
                ioWriterDefault = io.MultiWriter(os.Stdout, defaultLogFile)
        } else if isStdOut && !isFileOut {
                ioWriterDefault = os.Stdout
        }

        ioWriterSecurity := io.MultiWriter(ioWriterDefault, secLogFile)
        commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, nil, ioWriterDefault, false)
        commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, nil, ioWriterSecurity, false)

        slog.Trace("sec log initiated")
        log.Trace("loggers setup finished")
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}
        var err error
        secLogFile, err = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0755)
        if err != nil {
                log.Errorf("Could not open Security log file")
        }
        os.Chmod(constants.SecurityLogFile, 0664)
        defaultLogFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0755)
        if err != nil {
                log.Errorf("Could not open default log file")
        }
        os.Chmod(constants.LogFile, 0664)

        defer secLogFile.Close()
        defer defaultLogFile.Close()

        //bin := args[0]
        isStdOut := false
        isCMSConsoleEnabled := os.Getenv("SVS_ENABLE_CONSOLE_LOG")
        if isCMSConsoleEnabled == "true" {
                isStdOut = true
        }
        a.configureLogs(isStdOut, true)
        cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		return errors.New("Unrecognized command: " + args[1])	
	case "list":
                if len(args) < 3 {
                        a.printUsage()
                        os.Exit(1)
                }
                return a.PrintDirFileContents(args[2])
	case "run":
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting SVS service")
		}
	case "-help":
		fallthrough
	case "--h":
		fallthrough
	case "--help":
		fallthrough
	case "help":
		a.printUsage()
	case "start":
		return a.start()
	case "stop":
		return a.stop()
	case "status":
		return a.status()
	case "uninstall":
		var keepConfig bool
		flag.CommandLine.BoolVar(&keepConfig, "keep-config", false, "keep config when uninstalling")
		flag.CommandLine.Parse(args[2:])
		a.uninstall(keepConfig)
		os.Exit(0)
	case "version":
		fmt.Fprintf(a.consoleWriter(), "sgx verification service %s-%s\n", version.Version, version.GitHash)
	case "setup":
		var context setup.Context
		if len(args) <= 2 {
			a.printUsage()
			log.Error("app:Run() Invalid command")
			os.Exit(1)
		}
		if args[2] != "admin" &&
			args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "server" &&
			args[2] != "all" &&
			args[2] != "tls" &&
			args[2] != "jwt" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		valid_err := validateSetupArgs(args[2], args[3:])
		if valid_err != nil {
			return errors.Wrap(valid_err, "app:Run() Invalid setup task arguments")
		}

		a.Config = config.Global()
		err := a.Config.SaveConfiguration(context)
		if err != nil {
			fmt.Println("Error saving configuration: " + err.Error())
			os.Exit(1)
		}
		task := strings.ToLower(args[2])
		flags := args[3:]
		
		a.Config = config.Global()
		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
                                        Flags:         args,
					CmsBaseURL:    a.Config.CMSBaseUrl,
                                        CaCertDirPath: constants.TrustedCAsStoreDir,
                                        ConsoleWriter: os.Stdout,
                                },
				setup.Download_Cert{
                                        Flags:              args,
					CmsBaseURL:         a.Config.CMSBaseUrl,
                                        KeyFile:            path.Join(a.configDir(), constants.TLSKeyFile),
                                        CertFile:           path.Join(a.configDir(), constants.TLSCertFile),
                                        KeyAlgorithm:       constants.DefaultKeyAlgorithm,
                                        KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
                                        Subject: pkix.Name{
                                                Country:      []string{a.Config.Subject.Country},
                                                Organization: []string{a.Config.Subject.Organization},
                                                Locality:     []string{a.Config.Subject.Locality},
                                                Province:     []string{a.Config.Subject.Province},
                                                CommonName:   a.Config.Subject.TLSCertCommonName,
                                        },

                                        SanList:            constants.DefaultAasTlsSan, 
                                        CertType:           "TLS",
                                        CaCertsDir:         constants.TrustedCAsStoreDir,
                                        BearerToken:        "",
                                        ConsoleWriter:      os.Stdout,
                                },
				tasks.Server{
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
			log.WithError(err).Error("Error running setup")
			fmt.Println("Error running setup: ", err)
			return err
		}
	}
	return nil
}

func (a *App) retrieveJWTSigningCerts() error {
	return nil
}

func (a *App) startServer() error {
	log.Trace("app:startServer() Entering")
	defer log.Trace("app:startServer() Leaving")

	c := a.configuration()
	// Create Router, set routes
	r := mux.NewRouter()
	sr := r.PathPrefix("/svs/v1/").Subrouter()
        //sr.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, a.retrieveJWTSigningCerts))
        func(setters ...func(*mux.Router,*config.Configuration)) {
                for _, setter := range setters {
                        setter(sr,c)
                }
        }(resource.QuoteVerifyCB)

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
		Addr:      fmt.Sprintf(":%d", c.Port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	proc.AddTask()
	go func() {
		defer proc.TaskDone()
		proc.AddTask()

		// dispatch web server go routine
		go func() {
			defer proc.TaskDone()
			tlsCert := path.Join(a.configDir(), constants.TLSCertFile)
			tlsKey := path.Join(a.configDir(), constants.TLSKeyFile)
			if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
				proc.SetError(fmt.Errorf("HTTPS server error : %v", err))
				proc.EndProcess()
			}
		}()

		fmt.Fprintln(a.consoleWriter(), "SGX verification Service is running")
		<-proc.QuitChan
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Shutdown(ctx); err != nil {
			slog.WithError(err).Info("Failed to gracefully shutdown webserver")
			errors.Wrap(err, "app:startServer() Failed to gracefully shutdown webserver")
		}
		time.Sleep(time.Millisecond*200)
	}()
	proc.WaitForQuitAndCleanup(10 * time.Second)
	return nil
}

func (a *App) start() error {
	log.Trace("app:start() Entering")
	defer log.Trace("app:start() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start svs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:start() Could not locate systemctl to start application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "svs"}, os.Environ())
}

func (a *App) stop() error {
	log.Trace("app:stop() Entering")
	defer log.Trace("app:stop() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop svs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:stop() Could not locate systemctl to stop application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "svs"}, os.Environ())
}

func (a *App) status() error {
	log.Trace("app:status() Entering")
	defer log.Trace("app:status() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status svs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:status() Could not locate systemctl to check status of application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "svs"}, os.Environ())
}

func (a *App) uninstall(keepConfig bool) {
	log.Trace("app:uninstall() Entering")
	defer log.Trace("app:uninstall() Leaving")

	fmt.Println("Uninstalling sgx Verification Service")
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

	if !keepConfig {
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
	fmt.Fprintln(a.consoleWriter(), "sgx Verification Service uninstalled")
	a.stop()
}
func removeService() {
	log.Trace("app:removeService() Entering")
	defer log.Trace("app:removeService() Leaving")

	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove sgx Verification Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {
	log.Trace("app:validateCmdAndEnv() Entering")
	defer log.Trace("app:validateCmdAndEnv() Leaving")

	env_names := make([]string, 0)
	for k, _ := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, valid_err := validation.ValidateEnvList(env_names)
	if valid_err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.Wrap(valid_err, "app:validateCmdAndEnv() Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {
	log.Trace("app:validateSetupArgs() Entering")
	defer log.Trace("app:validateSetupArgs() Leaving")

	var fs *flag.FlagSet

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
		return nil

	case "admin":

                env_names_cmd_opts := map[string]string{
                        "SVS_ADMIN_USERNAME": "user",
                        "SVS_ADMIN_PASSWORD": "pass",
                }

                fs = flag.NewFlagSet("admin", flag.ContinueOnError)
                fs.String("user", "", "Username for admin authentication")
                fs.String("pass", "", "Password for admin authentication")

                err := fs.Parse(args)
                if err != nil {
                        return fmt.Errorf("Fail to parse arguments: %s", err.Error())
                }
                return validateCmdAndEnv(env_names_cmd_opts, fs)

        case "reghost":

                env_names_cmd_opts := map[string]string{
                        "SVS_REG_HOST_USERNAME": "user",
                        "SVS_REG_HOST_PASSWORD": "pass",
                }

                fs = flag.NewFlagSet("reghost", flag.ContinueOnError)
                fs.String("user", "", "Username for host registration")
                fs.String("pass", "", "Password for host registration")

                err := fs.Parse(args)
                if err != nil {
                        return fmt.Errorf("Fail to parse arguments: %s", err.Error())
                }
                return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "server":
		return nil

	case "tls":

		env_names_cmd_opts := map[string]string{
			"SVS_TLS_HOST_NAMES": "host_names",
		}

		fs = flag.NewFlagSet("tls", flag.ContinueOnError)
		fs.String("host_names", "", "comma separated list of hostnames to add to TLS cert")
		fs.Bool("force", false, "force run of setup task")

		err := fs.Parse(args)
		if err != nil {
			return errors.Wrap(err, "app:validateCmdAndEnv() Fail to parse arguments")
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "all":
		if len(args) != 0 {
			return errors.New("app:validateCmdAndEnv() Please setup the arguments with env")
		}
	case "jwt":
		return nil
	}

	return nil
}
func (a* App) PrintDirFileContents(dir string) error {
	log.Trace("app:PrintDirFileContents() Entering")
	defer log.Trace("app:PrintDirFileContents() Leaving")

        if dir == "" {
                return fmt.Errorf("PrintDirFileContents needs a directory path to look for files")
        }
        data, err := cos.GetDirFileContents(dir, "")
        if err != nil {
                return errors.Wrap(err, "app:PrintDirFileContents() Fail to get file content")
        }
        for i, fileData := range data {
                fmt.Println("File :", i)
                fmt.Printf("%s",fileData)
        }
        return nil
}

