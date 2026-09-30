# dns-watcher — external "router" for an anycast pair without Cisco: watches the nodes' readiness probe and
# points the service address at the node where it is open (docs/INSTALL/reference/07-dns-watcher.md).
# Go standard library only; output is the repo's bin/dns-watcher.
REVISION := $(shell git -C ../.. rev-parse --short HEAD 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo unknown)
LDFLAGS  := -s -w -X main.revision=$(REVISION)

.PHONY: build check
build:
	@mkdir -p ../../bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o ../../bin/dns-watcher .
	@echo "built: ../../bin/dns-watcher (revision $(REVISION))"
check:
	gofmt -l . | (! grep .) && go vet ./...
