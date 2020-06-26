# SGX Verification Service

`SGX Verification Service` is a web service whose job is to verify SGX ECDSA Quotes

## Key features
- Verify if PCK Certificate in a quote is genuine
- Verify TcbInfo, PCKCRL, QEIdentity for a platform
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- Go 1.13.1 or newer

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go 1.14.1` or newer
The `Certificate Management Service` requires Go version 11.4 that has support for `go modules`. The build was validated with version 14.1 version of `go`. It is recommended that you use a newer version of `go` - but please keep in mind that the product has been validated with 1.14.1 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -xzf go1.14.2.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build SGX Verification service

- Git clone the SGX Verification service
- Run scripts to build the SGX Verification service

```shell
git clone https://github.com/intel-secl/sgx-verification-service.git
cd sgx-verification-service
make all
```

### Deploy
```console
> ./sqvs-*.bin
```

### Manage service
* Start service
    * sqvs start
* Stop service
    * sqvs stop
* Restart service
    * sqvs restart
* Status of service
    * sqvs status

# Third Party Dependencies

## Certificate Management Service

### Direct dependencies

| Name        | Repo URL                    | Minimum Version Required           |
| ----------- | --------------------------- | :--------------------------------: |
| uuid        | github.com/google/uuid      | v1.1.1                             |
| context     | github.com/gorilla/context  | v1.1.1                             |
| handlers    | github.com/gorilla/handlers | v1.4.2                             |
| mux         | github.com/gorilla/mux      | v1.7.4                             |
| jwt-go      | github.com/dgrijalva/jwt-go | v3.2.0+incompatible                |
| gorm        | github.com/jinzhu/gorm      | v1.9.12                            |
| logrus      | github.com/sirupsen/logrus  | v1.4.2                             |
| testify     | github.com/stretchr/testify | v1.5.1                             |
| crypto      | golang.org/x/crypto         | v0.0.0-20200320181102-891825fb96df |
| time        | golang.org/x/time           | v0.0.0-20191024005414-555d28b269f0 |
| yaml.v2     | gopkg.in/yaml.v2            | v2.2.2                             |
| restruct    | gopkg.in/restruct           | v1.0.0                             |
| authservice | intel/isecl/authservice     | v2.1/develop                       |
| common      | intel/isecl/lib/common      | v2.1/develo                        |

### Indirect Dependencies

| Repo URL                     | Minimum version required           |
| -----------------------------| :--------------------------------: |
| github.com/jinzhu/inflection | v1.0.0                             |

*Note: All dependencies are listed in go.mod*
