# Pulse daemons. Like dns-ha, built on the dev machine; sites receive a ready static binary
# (no Go toolchain, no libc version dependency).
#
#   make build  — linux/amd64, CGO_ENABLED=0, with embedded revision
#   make check  — gofmt + go vet (no automated tests)
#   make sha    — artifact checksums
BINS     := pulse-server pulse-agent
REVISION := $(shell git -C ../.. rev-parse --short HEAD 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo unknown)
VERSION  := $(shell git -C ../.. describe --tags --always 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo dev)
# No build time in the identity on purpose: it breaks reproducibility.
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.revision=$(REVISION)

.PHONY: build check sha fmt clean
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
	sha256sum ../../bin/pulse-server ../../bin/pulse-agent
clean:
	rm -f ../../bin/pulse-server ../../bin/pulse-agent
