GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: sqvs installer all test clean

sqvs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/sqvs/version.BuildDate=$(BUILDDATE) -X intel/isecl/sqvs/version.Version=$(VERSION) -X intel/isecl/sqvs/version.GitHash=$(GITCOMMIT)" -o out/sqvs

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

all: clean installer test

clean:
	rm -f cover.*
	rm -rf out/
