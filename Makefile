GO ?= go
COMMANDS := backhaul-probe neo-tunnel

.PHONY: test build linux vet

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p build/native
	@set -e; for command in $(COMMANDS); do \
		$(GO) build -trimpath -o build/native/$$command ./cmd/$$command; \
	done

linux:
	@set -e; for arch in amd64 arm64; do \
		mkdir -p build/linux-$$arch; \
		for command in $(COMMANDS); do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -o build/linux-$$arch/$$command ./cmd/$$command; \
		done; \
	done
