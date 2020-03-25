GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: svs installer all test clean

svs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/svs/version.BuildDate=$(BUILDDATE) -X intel/isecl/svs/version.Version=$(VERSION) -X intel/isecl/svs/version.GitHash=$(GITCOMMIT)" -o out/svs

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

installer: svs
	mkdir -p out/installer
	cp dist/linux/svs.service out/installer/svs.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/svs out/installer/svs
	makeself out/installer out/svs-$(VERSION).bin "sgx Verification Service $(VERSION)" ./install.sh

all: clean installer test

clean:
	rm -f cover.*
	rm -rf out/
