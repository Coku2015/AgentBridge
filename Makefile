## AgentBridge build targets
## Single-binary, cross-platform, CGO-disabled release builds.

PKG        := github.com/Coku2015/agentbridge
VERSION    ?= dev
COMMIT     ?= none
# cmd/agentbridge is a `main` package, so Go's -X linker keys use the package
# name (`main.Version`), not the module import path.
LDFLAGS    := -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
GOFLAGS    := -trimpath
CGO_ENABLED ?= 0

# Vite build output is the go:embed source for the embedded Web UI.
WEB_DIST   := internal/httpserver/web/dist
CMD        := ./cmd/agentbridge
OUTDIR     := build
RELEASEDIR := release

.DEFAULT_GOAL := build-all

## Build only the host binary (no frontend rebuild). Fastest dev loop.
.PHONY: build
build:
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUTDIR)/agentbridge $(CMD)

## Build frontend then all four platform binaries.
.PHONY: build-all
build-all: web
	$(MAKE) build-linux build-darwin-amd64 build-darwin-arm64 build-windows

.PHONY: build-linux
build-linux:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUTDIR)/agentbridge-linux-amd64 $(CMD)

.PHONY: build-darwin-amd64
build-darwin-amd64:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUTDIR)/agentbridge-darwin-amd64 $(CMD)

.PHONY: build-darwin-arm64
build-darwin-arm64:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUTDIR)/agentbridge-darwin-arm64 $(CMD)

.PHONY: build-windows
build-windows:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUTDIR)/agentbridge-windows-amd64.exe $(CMD)

## Build versioned archives and SHA-256 checksums for a GitHub Release.
.PHONY: release release-version-check
release-version-check:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must be a release tag such as v0.1.0" >&2; exit 1)

release: release-version-check web
	$(MAKE) build-linux build-darwin-amd64 build-darwin-arm64 build-windows VERSION=$(VERSION) COMMIT=$(COMMIT)
	rm -rf $(RELEASEDIR)
	mkdir -p $(RELEASEDIR)/staging/linux-amd64 $(RELEASEDIR)/staging/darwin-amd64 $(RELEASEDIR)/staging/darwin-arm64 $(RELEASEDIR)/staging/windows-amd64
	cp $(OUTDIR)/agentbridge-linux-amd64 $(RELEASEDIR)/staging/linux-amd64/agentbridge
	cp $(OUTDIR)/agentbridge-darwin-amd64 $(RELEASEDIR)/staging/darwin-amd64/agentbridge
	cp $(OUTDIR)/agentbridge-darwin-arm64 $(RELEASEDIR)/staging/darwin-arm64/agentbridge
	cp $(OUTDIR)/agentbridge-windows-amd64.exe $(RELEASEDIR)/staging/windows-amd64/agentbridge.exe
	tar -czf $(RELEASEDIR)/agentbridge-$(VERSION)-linux-amd64.tar.gz -C $(RELEASEDIR)/staging/linux-amd64 agentbridge
	tar -czf $(RELEASEDIR)/agentbridge-$(VERSION)-darwin-amd64.tar.gz -C $(RELEASEDIR)/staging/darwin-amd64 agentbridge
	tar -czf $(RELEASEDIR)/agentbridge-$(VERSION)-darwin-arm64.tar.gz -C $(RELEASEDIR)/staging/darwin-arm64 agentbridge
	cd $(RELEASEDIR)/staging/windows-amd64 && zip -q ../../agentbridge-$(VERSION)-windows-amd64.zip agentbridge.exe
	rm -rf $(RELEASEDIR)/staging
	cd $(RELEASEDIR) && shasum -a 256 agentbridge-$(VERSION)-*.tar.gz agentbridge-$(VERSION)-*.zip > checksums.txt

## Build embedded frontend into $(WEB_DIST).
.PHONY: web
web:
	cd web && npm ci && npm run build
	touch $(WEB_DIST)/.gitkeep

## Run the embedded Web UI dev server with HMR (proxies API to Go server).
.PHONY: web-dev
web-dev:
	cd web && npm run dev

## Run the Go backend in localhost serve mode.
.PHONY: run
run:
	go run $(CMD)

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	gofmt -s -w .
	go mod verify

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: clean
clean:
	rm -rf $(OUTDIR) $(WEB_DIST)
	mkdir -p $(WEB_DIST)

.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
