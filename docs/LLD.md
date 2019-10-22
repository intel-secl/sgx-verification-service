
# Certificate Management Service Low Level Documentation

## Acronyms
|     | Description                       |
|-----|-----------------------------------|
| CMS | Certificate Management Service    |

# Overview
The `Certificate Management Service` is the first stop for all certificate related activities in ISecL. CMS holds the root certificate which is used to sign all other certificates e.g Signing, TLS certificates. Each communication between ISecL components will be based on certificates distributed by CMS.

The `Certificate Management Service` has following core functionalities:

# API Endpoints

## Root CA certificates

### GET `/cms/v1/ca-certificates`
Retrieve the root CA Certificate configured in CMS
- Accept: `application/x-pem-file`

Example Response:
```pem
-----BEGIN CERTIFICATE-----
MIIEEjCCAnqgAwIBAgIBADANBgkqhkiG9w0BAQwFADA6MQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0MxDjAMBgNVBAoTBUlOVEVMMQ4wDAYDVQQDEwVDTVNDQTAeFw0x
OTA2MDYxMTMzMDhaFw0yNDA2MDYxMTMzMDlaMDoxCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJTQzEOMAwGA1UEChMFSU5URUwxDjAMBgNVBAMTBUNNU0NBMIIBojANBgkq
hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtlTImEPVSFiym+fVac/JyqJsu9E+IkYp
vgZlIOTZltnMrxH1SoEc2ttc3EZakOqcD3kzm/7v+uxJ5v0z3xHYxXyrLeZxLlwI
gGKgjoOpIMuC4gNvng4PHFS+LKkAPdMvER2Is3//w5H3Aqpz1t44MhXcDAGA8aYV
SaSG0dRgiA/2YjU/L7S5wb3TzziS9Vu7RPq1dBiqD8UMnCMkkSDlVbGVe6knZyEi
7WIsNFVSL03vH2iVpy7XCn3HnqcDVX0Hs5gZO5oW1p4tLkn8UWxavls+x8SVFumc
DztWT0YSo1LKkkpnVYfb0TDLeC7A5e9xljmT5hI68U6Kw27Kr3WAv5B99WLnLsfK
1RPEGZ0vHAJHABIMI5OqfqKBk2RdXu8rBqcSTQfevXLze7k/gF6M3XSoyz5oNOKC
auv+1AfZ/Uo/zehy4tGP3hc4WDmsx+VG5qF7Ikn4+KB7vnybp6bplVhqDf/T6NZr
MWL9FNobTz6SdTW+d/lVhhm5AM6/zY/7AgMBAAGjIzAhMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDAUAA4IBgQCBuBoEqbOIG8QT
zOvAQJ0db/bMXDn2l/bh7Lxv2zEpVjtRoOnegCvUVEr0NpuxshSI2S5zxgsJIqEd
sDBG6M7dwGxBrXvsYB91xAaJDuDV4Em5D/sXum8TzwpULRnRCiEmE98oaffNg6Ed
Dz/BC8n6YFyjxYsZuHfGK3zt3kixPRWIiE+I5yuHKhrSs8FWZYeAykeu6c8z76dL
jkO5FIvn4QVtzvPdeKDmtMKAdiDUYHT54zTXW619DuB/5YRReYQbJrSIhb49yAx9
Ub8Dsza57pQ/eTzilsxDauUoNjq3H+5RHpKhdeJwnUREfReZWho92W9FojfsKm+z
BeHCGqvZE4TuWmTNrS51lryvZLzlLpdxUeMNL5n5yV3jM/cheRM9QZU+NA04gphx
UMuRV7NUwYbn003sVkKvvdYm8dTSkjfAm6W6Lhn2idRX5O5k4KCgT4I535ae6aHq
MYVYqMHd9AuoWtyd1yATQppyTBbPrrgj5wI2TUMNNmk5JGIN6WQ=
-----END CERTIFICATE-----
```
## Certificates
### POST `/cms/v1/certificates?certType=TLS`

Signs certificates for the requested CSR

- Authorization: `JWT Token`
- Content-Type: `application/x-pem-file`
- Accept: `application/x-pem-file`
- Parameters: `certType=TLS|JWT-Signing|Flavor-Signing`
```pem
-----BEGIN CERTIFICATE REQUEST-----
MIIDuTCCAiECAQAwRTELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktOMQswCQYDVQQH
DAJCQTEOMAwGA1UECgwFSU5URUwxDDAKBgNVBAMMA0FBUzCCAaIwDQYJKoZIhvcN
AQEBBQADggGPADCCAYoCggGBAMJ79fqjJ5mYk1JuBTxtjEwS4ogSRxFGtLaX28So
//Xsj2HXSGPH4LDpy/0hJJteWhUjnTLu+i9s0tHAyA1yp5/Ao0WyZu/aNV3lRciZ
XaD9vjEwc8rUJcEwq6TYM+iiTjbpKr+42Cei0GZBRcToamoBP9TGUg6P4YaSzivs
de2bhnq/XBGT01tbI6sLL7r0d5txTey1iuCIkcj5fDpBqZEC5Gk244xLZXmO6NvC
Fvg9XJF3JkmBaBQWWvisBPEHERKbcKZH+kA81RFNkag1RiR/1OVczdxIFQPwdocd
ozYavegJrsGcaGFG+iTWAQ5ZJVf3zj3ivuQjp/ZnOd4ZP9YqpD6BQp3eTGzoh47t
gvIJEf+CRqigEjwNVGIGkxoDXfsHNmRFqXyu/zSbgL9DgEYcMAMiCbGBe3JUm4lq
XVSpmRt80PJ4KlNW+RKJ5X+ABvxDfd5DXrFmKwtPuqQMApZ76uuMPTiJojTCUVP+
Bxd57xWun5HBqyDiOhUqTfAMkwIDAQABoC8wLQYJKoZIhvcNAQkOMSAwHjAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQwFAAOCAYEAhpQw
4UdNmjErznU4Dx34bhE9AW/8ltmmn/DxIXdTcH+fDkuJsVpTvdQApE15kfVaKyNc
09ePTt5UMxqnrv+N46eRWSz5Zk/L/K8EFRCb3GsiiZZNVOHoKmyCN7AhY0P3Bd11
sLmjjaOh9AnBpoQQwB/klwWLrmsaUhRrgaVBOX01xevX3kGFKnpd0lIi84IYbXpB
scrjCbMcbTTJZKhDJMKJzuQ09u9nB2jDDTqaolb6Mxygz3xOGciYoxzeXHQVW9q0
sOvGVXAN13miJ0AmD9dL962lY99dIPWTdMc6adMdPtuO9S9o4Ytju2IBQTJw7HWb
uDl7pZ3CzTchOaW7gq99QO4okcov0woHiUgJoQZm3KwcmYvN6GYNdoCnbmudwroF
7bAGLGBUjBhRw2lAEc/5xwp6ydqcxfGKk7pbkQCNLBe95jDiwHaXhbQYycHj2R7S
aWbBQF4/0umNPmluA5LVOCeuN0niPaOYBUWPelMr9rhQqmaw+tlKuGQE4OGz
-----END CERTIFICATE REQUEST-----
```
Example Response:
```pem
-----BEGIN CERTIFICATE-----
MIIDvDCCAiSgAwIBAgIBAjANBgkqhkiG9w0BAQwFADAQMQ4wDAYDVQQDEwVDTVND
QTAeFw0xOTA2MDcwNjQxNDhaFw0yMDA2MDcwNjQxNDhaMA4xDDAKBgNVBAMTA0FB
UzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKN2TnQ8eQL2utyYEAZ0
0VjJZAxTPR7cXiNE8k4bHUQ7GlGIYLyHOBP3ow/MnFh7tccS1vXh1l9Bz6MypDd3
hRmaBnCy7NzQOuAZ3nj/icXWQt3vVxEU4ibZZB5n9jtBQ6184kwgxB/V3kKFgHp/
PtZLDzim5ZwzU8naF/wlV2KAx+nEqjB4DBCh4R/RSpX+hfsk+37j7f2MEPmcqNAV
tH7/2/HmLdMuwQu8RRH4Icfmu1Rj2J0Rbc2DYQMtwNX+WrX5Ln5EoXA7W+iEmxqx
1k7QsEaJLHIQKNjogPOKLeGjb4mdM3BLxIt6UDiwNsEVGNvjOnqtqamNNxhRGUN8
MQSJPg+xGIwXgQeW7JDT/J225z0n6KCurbf56jj1Lrq7Lb3Qu+yRnPAUDiQhdYpT
d3c57mrGQvMUBo5dI8O4ldTD5EPeV77rO/MdZn03UOVYM4XCkQs6TEb/vLdNYtvH
7DlE1hfeF8rEVy0Xnd6x16MS4NTaFbmSFBayvSTou1PuiwIDAQABoyMwITAOBgNV
HQ8BAf8EBAMCBaAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOCAYEA
JhnGr8qTmUwMq1fTZKomhJ2zkCZOd6v+Nlnnp3iKiQdNah1knfUoarPwiyJSbBvH
b3FUDFber50Gqul6v8qsrlxZN25Zj2QGTmmhIDFg0p+/gp7lhgVGEJlXko/UaIHe
OkDsL8fZ7fzm649E2gYt7unyMwtLZnMlylegprQfhwug4gOx0MVveDjKt0wVyxTV
HG7OJXcJ9TIfJ9ZmlqYBEfNHKChdkay1DBf4/p1qDkSIboM3+mGc0IbvZaOBJ+6K
MmBpvAZZeZfTkPVwcqmEd3r8dugALZQmi2dvukU9o6acgdS0Usk2GEbvwSdl6cUF
9TzvCGdh1lFLv9/cvPGr8zwWJaW4N0/xu2fl+aBHnUb8NLNhgLVfUUoDp+giPpkG
1VKZ06TLlS59IrD3i0j+1wAUx0kPUBVxzTmGca7Vg3s/cX023WppmLVln9lq0YQI
c2sZh8wCIwMlFTf9LF8FTHLrgQwCU8aiS93qZehDeiFqu57gNI+0+apBh2218FuX
-----END CERTIFICATE-----
```
Error Responses:
```
401: Unauthorized - Missing or invalid token
403: Forbidden    - Bearer token does contain the required role for the requested CSR
```

#### NOTE
Extensions validation will not happen in CMS, KeyUsages and ExtendedKeyUsages will be populated on the basis of certificate type

## User Stories
### Download Root CA certificate
As a user, I want to download Root CA certificate from CMS.

### Get CSR signed from root CA 
As a user, I want to get my TLS/JWT CSR signed from CMS. 

### Recreate Root CA certificate
As an administrator, I want to create or recreate Root CA certificate of CMS.

### Recreate TLS certificate
As an administrator, I want to create or recreate TLS certificate of CMS.

### Recreate Authentication Token
As an administrator, I want to create or recreate Authentication token for CMS.

## Integration User Stories
### AAS Download TLS certificate using setup Auth Token
As an administrator, I want to download TLS certificate from CMS while installation of AAS or using setup command, using Authentication Token provided by CMS at setup

### WLS Download Root CA certificate
As an administrator, I want to download Root CA certificate from CMS while installation of WLS or using setup command

### WLS Download TLS certificate
As an administrator, I want to download TLS certificate from CMS while installation of WLS or using setup command

### WLA Download Root CA certificate
As an administrator, I want to download Root CA certificate from CMS while installation of WLA or using setup command


# Certificate Management Service Installaton

There are two modes of installation:

1. Bare Metal
2. Container

## Bare Metal Installation

The daemon will create and use the following files on the OS:

1. /var/log/cms/cms.log
2. /var/log/cms/http.log
3. /var/lib/cms/* (misc files)
4. /etc/cms/config.yml (Configuration)
5. /usr/\*/bin/cms(executable binary)
6. /var/lib/cms/root-ca-key.pem (Root CA key)
7. /var/lib/cms/root-ca-cert.pem (Root CA cert)
8. /var/lib/cms/tls-key.pem (TLS key)
9. /var/lib/cms/tls-cert.pem (TLS cert)

## Container Installation

Since `CMS` is a standalone web service, container deployment is trivial.

All necessary setup options should be readable from environment variables, so the container can be spun up by only passing environment variables

# CMS Features
## Certificate Management Service

### Authentication Defender

The authenticaiton defender is a designed to thwart disctionary based attacks by locking the account for a specified time. If there are x number of attempts in y time, the account would be locked out for a period of z time. The current default is 5 attempts in 5 minutes and you are locked out for 15 minutes. These may be configured in the config file and is loaded when the daemon restarts.

# Command Line Operations

## Setup

Available setup tasks:
- root_ca
- tls
- cms_auth_token
- all


### Setup - Root CA

```bash
> cms setup root_ca [--force]
```
This command can be used to generate key pairs for root CA and create the self-signed root CA certificates. ‘--force’ parameter will force to regenerate key pairs/certificates and replace if already present.

Command implementation details –

 1. creates RSA 3072 bits long key pair
 2. generate root CA certificate
 3. store root key pair in config directory
 4. store root CA certificate in config directory


### Setup - TLS

```bash
> cms setup tls [--force]
```
This command can be used to generate key pair and create the signed certificates. ‘--force’ parameter will force to regenerate key pairs/certificate and replace if already present. 

Command implementation details–
 1. creates RSA 3072 bits long key pair
 2. generate TLS certificate
 3. store root key pair in config directory
 4. store TLS certificate in in config directory

### Setup - CMS AUTH TOKEN

```bash
> cms setup cms_auth_token [--force]
```
This command can be used to generate key pair and create the self signed certificates. Using which new token is generated which can be used in AAS for initial setup, ‘--force’ parameter will force to regenerate key pairs/certificate and regenerate auth token. 

Command implementation details–
 1. creates RSA 3072 bits long key pair
 2. generate self signed signing certificate
 3. store certificate in '/etc/cms/jwt' config directory
 4. outputs token on console

### Predefined AAS roles
```json
{
  "roles": [
    {
      "service": "CMS",
      "name": "CertApprover",
      "context": "CN=AAS JWT Signing Certificate;CERTTYPE=JWT-Signing"
    },
    {
      "service": "CMS",
      "name": "CertApprover",
      "context": "CN=AAS TLS Certificate;SAN=127.0.0.1,localhost;CERTTYPE=TLS"
    }
  ],
  "exp": 1563988236,
  "iat": 1563901836,
  "iss": "CMS JWT Signing",
  "sub": "CMS JWT Token"
}
```

## Start/Stop

```bash
> cms start
  Certificate Management Service started
> cms stop
  Certificate Management Service stopped
```

## Uninstall

```bash
> cms uninstall 
  Certificate Management Service uninstalled
```
Uninstalls Certificate Management Service

## Help

```bash
> cms (help|-h|-help)
  Usage: cms <command> <flags>
    Commands:
    - setup
    - help
    - start
    - stop
    - status
    - uninstall
    - version
```

## Version

```bash
> cms version
    Certificate Management Service v1.0.0 build 9cf83e2
```

## Environment Details
There are several parameters associated with CMS installation and setup task. The following provides an explanation of how they can be used
```bash
#Environment Variables
#Default is false, this is used to skip all setup tasks at the time of installation
CMS_NOSETUP=false

#CMS port details, default port is 8445
CMS_PORT=8445

#CMS certificate specific properties
#Default is 5 years
CMS_CA_CERT_VALIDITY=5 
CMS_CA_ORGANIZATION=INTEL
CMS_CA_LOCALITY=SC
CMS_CA_PROVINCE=SF
CMS_CA_COUNTRY=US

#SAN list for TLS certificate
CMS_HOST_NAMES=127.0.0.1,localhost

#These details are for future work when CMS need to support multiple algorithms
CMS_KEY_ALGORITHM="rsa"
CMS_KEY_ALGORITHM_LENGTH=3072

#Config Parameters
port: 8443
loglevel: info
cacertvalidity: 5
organization: "INTEL"
locality: "SC"
province: "SF"
country: "US"
#These details are for future work when CMS need to support multiple algorithms
keyalgorithm: rsa
keyalgorithmlength: 3072
#Setup token will have following AAS roles defined
aasjwtcn: "AAS JWT Signing Certificate"
aastlscn: "AAS TLS Certificate"
aastlssan: "127.0.0.1,localhost"
authdefender:
  maxattempts: 5
  intervalmins: 5
  lockoutdurationmins: 15

#Environment variables will take higher precedence.
```