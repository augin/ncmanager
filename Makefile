.PHONY: build run clean install setup

BINARY = ncmanager
GO = go
GOFLAGS = -ldflags="-s -w"
# Static binary without cgo: the toolchain's gcc may emit AVX instructions
# (e.g. on newer CI runners) which crash on CPUs without AVX.
export CGO_ENABLED = 0

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) .

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf dist/

install:
	install -Dm755 $(BINARY) /usr/local/bin/$(BINARY)

setup:
	sudo apt update
	sudo apt install -y wireguard wireguard-tools iptables
	mkdir -p data static/css static/js templates
