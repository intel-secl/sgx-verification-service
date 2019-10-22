GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: svs installer docker all test clean

svs:
	env GOOS=linux go build -ldflags "-X intel/isecl/svs/version.Version=$(VERSION) -X intel/isecl/svs/version.GitHash=$(GITCOMMIT)" -o out/svs

test:
	go test ./...

installer: svs
	mkdir -p out/installer
	cp dist/linux/svs.service out/installer/svs.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/svs out/installer/svs
	makeself out/installer out/svs-$(VERSION).bin "sgx Verification Service $(VERSION)" ./install.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/svs:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/svs:latest > ./out/docker-svs-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-svs
	cp dist/docker/docker-compose.yml out/docker-svs/docker-compose
	cp dist/docker/entrypoint.sh out/docker-svs/entrypoint.sh && chmod +x out/docker-svs/entrypoint.sh
	cp dist/docker/README.md out/docker-svs/README.md
	cp out/svs-$(VERSION).bin out/docker-svs/svs-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-svs/Dockerfile
	zip -r out/docker-svs.zip out/docker-svs	

all: docker

clean:
	rm -f cover.*
	rm -f svs
	rm -rf out/
