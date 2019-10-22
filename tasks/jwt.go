package tasks

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"intel/isecl/svs/config"
	"intel/isecl/svs/constants"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"crypto/x509/pkix"
)

type JWT struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (jwt JWT) Run(c setup.Context) error {

	// no cms - should remove
	// 1. call CreateKeyPairAndCertificate
	// 2. save private key with pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}) to TokenSignKeyFile
	// 3. pem encode cert and save to TokenSignCertFile
	// 4. save to TrustedJWTSigningCertsDir with SavePemCertWithShortSha1FileName
	fmt.Fprintln(jwt.ConsoleWriter, "Running jwt setup...")
	if jwt.Config.Subject.JWTCertCommonName == "" {	
		jwt.Config.Subject.JWTCertCommonName, _ = c.GetenvString("SVS_JWT_CERT_CN", "SVS JWT Certificate Subject")
		if jwt.Config.Subject.JWTCertCommonName == "" {
			jwt.Config.Subject.JWTCertCommonName = constants.DefaultSvsJwtCn
		}
	}

	envJwtIncludeKid, _ := c.GetenvString("SVS_JWT_INCLUDE_KEYID", "SVS include key id in JWT Token")
	envJwtTokenDurationMins, _ := c.GetenvInt("SVS_JWT_TOKEN_DURATION_MINS", "SVS JWT Token duration in mins")
	envBearerToken, _ := c.GetenvString("BEARER_TOKEN", "bearer token")
	//set up the defaults

	jwt.Config.Token.IncludeKid = true
	if strings.ToLower(envJwtIncludeKid) == "false" {
		jwt.Config.Token.IncludeKid = false
	}
	
	force := false
	fs := flag.NewFlagSet("jwt", flag.ContinueOnError)
	fs.StringVar(&jwt.Config.Subject.JWTCertCommonName, "subj", jwt.Config.Subject.JWTCertCommonName, "JWT Signing Certificate Common Name")
	fs.StringVar(&envBearerToken, "token", envBearerToken, "Bearer Token for requesting certificates from CMS")
	fs.StringVar(&jwt.Config.CMSBaseUrl, "cms-url", jwt.Config.CMSBaseUrl, "CMS Base URL")
	fs.IntVar(&jwt.Config.Token.TokenDurationMins, "valid-mins", envJwtTokenDurationMins, "JWT Token validation minutes")
	fs.BoolVar(&jwt.Config.Token.IncludeKid, "keyid", jwt.Config.Token.IncludeKid, "JWT include Key ID")
	err := fs.Parse(jwt.Flags)
	if err != nil {
		return err
	}

	if jwt.Config.CMSBaseUrl == "" {
		return errors.New("JWT Certificate setup: need CMS url to obtain certificate")
	}

	if envBearerToken == "" {
		return errors.New("JWT Certificate setup: BEARER_TOKEN needed for downloading certificates from CMS")
	}
	
	if jwt.Validate(c) == nil &&
                !force {
                return nil
        }

	// let us call the method available in the common setup task to obtain certificate and
	privKeyDer, cert, err := setup.GetCertificateFromCMS("JWT-Signing", constants.DefaultKeyAlgorithm,
		constants.DefaultKeyAlgorithmLength, jwt.Config.CMSBaseUrl,
		pkix.Name{CommonName: jwt.Config.Subject.JWTCertCommonName,
			Organization: []string{jwt.Config.Subject.Organization},
			Country:      []string{jwt.Config.Subject.Country},
			Province:     []string{jwt.Config.Subject.Province},
			Locality:     []string{jwt.Config.Subject.Province},
		},
		"127.0.0.1, localhost", constants.TrustedCAsStoreDir,envBearerToken)
	//cert, privKeyDer, err := crypt.CreateKeyPairAndCertificate(envJwtCertSub, "", "", 0)
	if err != nil {
		return err
	}

	// write out the private key
	keyOut, err := os.OpenFile(constants.TokenSignKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	os.Chmod(constants.TokenSignKeyFile, 0640)
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}

	// write the token signing certificate to the specified location
	err = ioutil.WriteFile(constants.TokenSignCertFile, cert, 0640)
	if err != nil {
		fmt.Println("Could not store Certificate")
		return fmt.Errorf("Certificate setup: %v", err)
	}
	os.Chmod(constants.TokenSignCertFile, 0640)

	// write the same jwt certificate into the list of trusted jwt signing certificates so that the
	// token that is issued by SVS can be verified as well using the jwt library
	err = crypt.SavePemCertWithShortSha1FileName(cert, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		fmt.Println("Could not store Certificate")
		return fmt.Errorf("Certificate setup: %v", err)
	}

	return jwt.Config.Save()
}

func (jwt JWT) Validate(c setup.Context) error {

	if _, err := os.Stat(constants.TokenSignKeyFile); err != nil {
		if os.IsNotExist(err) {
			return err
		}
	}
	if _, err := os.Stat(constants.TokenSignCertFile); err != nil {
		if os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
