GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: sqvs installer all test clean

all: clean installer

sqvs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/sqvs/v3/version.BuildDate=$(BUILDDATE) -X intel/isecl/sqvs/v3/version.Version=$(VERSION) -X intel/isecl/sqvs/v3/version.GitHash=$(GITCOMMIT)" -o out/sqvs

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.25.0/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.23/swagger-codegen-cli-3.0.23.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc:
	mkdir -p out/swagger
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

installer: sqvs
	mkdir -p out/installer
	cp dist/linux/sqvs.service out/installer/sqvs.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/sqvs out/installer/sqvs
	makeself out/installer out/sqvs-$(VERSION).bin "sgx Verification Service $(VERSION)" ./install.sh

clean:
	rm -f cover.*
	rm -rf out/
