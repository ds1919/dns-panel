# dns-sync-worker — the panel's background scheduler (docs/INSTALL/reference/05-dns-agent.md).
# Go standard library only; output is the repo's bin/dns-sync-worker.
REVISION := $(shell git -C ../.. rev-parse --short HEAD 2>/dev/null || sed "s/^/v/" ../../VERSION 2>/dev/null || echo unknown)
LDFLAGS  := -s -w -X main.revision=$(REVISION)

.PHONY: build check
build:
	@mkdir -p ../../bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o ../../bin/dns-sync-worker .
	@echo "built: ../../bin/dns-sync-worker (revision $(REVISION))"
check:
	gofmt -l . | (! grep .) && go vet ./...
