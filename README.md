# SGX Verification Service

`SGX Verification Service` is a web service whose job is to verify SGX ECDSA Quotes

## Key features

- Verify if PCK Certificate in a quote is valid
- Verify TcbInfo, PCKCRL, QEIdentity for a platform
- RESTful APIs for easy and versatile access to above features

## System Requirements

- RHEL 8.2
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements

- git
- make
- makeself
- Go 1.14.1

## Step-By-Step Build Instructions

### Install required shell commands

#### Install tools from `dnf`

```shell
sudo dnf install -y git wget makeself
```

### Install `go 1.14.1`
The `SGX Verification Service` requires Go version 1.14.1 that has support for `go modules`. please keep in mind that the product has been validated with 1.14.1 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.

```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
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
git checkout v3.6.0
make
```

### Deploy
Update sqvs.env present in dist/linux folder with required env values and then run below command to deploy SQVS.

NOTE: Retrieve appropriate Trusted RootCA certificate files for SGX platform (trusted_rootca.pem for IceLake Sandbox PCS, trusted_rootca_icx_prod.pem for IceLake Live PCS and trusted_rootca_clx_prod.pem for CascadeLake Live PCS Server) from dist/linux directory in SQVS repository.

```shell
> ./out/sqvs-*.bin
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

## Third Party Dependencies

- Certificate Management Service

- Authentication and Authorization Service

### Direct dependencies

| Name        | Repo URL                     | Minimum Version Required           |
| ----------- | ---------------------------  | :--------------------------------: |
| handlers    | github.com/gorilla/handlers  | v1.4.2                             |
| mux         | github.com/gorilla/mux       | v1.7.4                             |
| errors      | github.com/pkg/errors        | v0.9.1                             |
| logrus      | github.com/sirupsen/logrus   | v1.5.0                             |
| testify     | github.com/stretchr/testify  | v1.5.1                             |
| yaml.v2     | gopkg.in/yaml.v2             | v2.4.0                             |
| restruct    | gopkg.in/restruct            | v1.0.0                             |
| common      | github.com/intel-secl/common | v3.5.0                             |
| clients     | github.com/intel-secl/clients| v3.5.0                             |

### Indirect Dependencies


*Note: All dependencies are listed in go.mod*
