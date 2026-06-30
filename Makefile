.PHONY: build run clean install setup

BINARY = ncmanager
GO = /usr/lib/go-1.24/bin/go
GOFLAGS = -ldflags="-s -w"

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
