# Build dns-ha (manager + agent). Built only on the dev machine: DNS nodes get a prebuilt static binary,
# no Go toolchain (docs/23-ha-manager.md §16, O3). Output goes to the repo bin/, mirroring /opt/dns-panel/bin.
#
#   make build   — linux/amd64, static (CGO_ENABLED=0), with embedded revision
#   make check   — gofmt + go vet (the project has no automated tests)
#   make sha     — artifact checksum (compared on the node after install)

BINS     := dns-ha-manager dns-ha-agent
REVISION := $(shell git -C ../.. rev-parse --short HEAD 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo unknown)
VERSION  := $(shell git -C ../.. describe --tags --always 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo dev)

# No build time in the identity on purpose: it breaks reproducibility. Revision identifies, sha256 verifies.
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.revision=$(REVISION)

.PHONY: build check sha clean fmt

build:
	@mkdir -p ../../bin
	@for b in $(BINS); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o ../../bin/$$b ./cmd/$$b || exit 1; \
		echo "built: ../../bin/$$b (revision $(REVISION))"; \
	done

check:
	gofmt -l . | (! grep .) || (echo "not formatted — run make fmt"; exit 1)
	go vet ./...

fmt:
	gofmt -w .

sha: build
	sha256sum ../../bin/dns-ha-manager ../../bin/dns-ha-agent

clean:
	rm -rf build
