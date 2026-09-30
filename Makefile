# DNS Panel — build and checks from the repository root.
#
# The repo tree deliberately mirrors the installed one (/opt/dns-panel): bin/ etc/ libexec/ www/.

GO_DIRS := src/dns-agent src/dns-sync-worker src/dns-ha src/dns-pulse src/dns-watcher
BINS    := dns-agent dns-sync-worker dns-ha-manager dns-ha-agent pulse-server pulse-agent dns-watcher

.PHONY: all build check fmt clean deb

all: build

# Go components put binaries into bin/, the same place they live in an installation.
build:
	@for d in $(GO_DIRS); do $(MAKE) -C $$d build || exit 1; done

# There are no automated tests (Perl or Go); the panel is verified by reading the code and using the live UI
# (docs/04-panel-code.md). What remains here catches errors cheaply: formatting and go vet.
check:
	@for d in $(GO_DIRS); do $(MAKE) -C $$d check || exit 1; done

fmt:
	@for d in $(GO_DIRS); do (cd $$d && gofmt -w .); done

clean:
	rm -rf $(addprefix bin/,$(BINS)) dist

# Debian packages (panel node, NS Pulse tester, watcher) into dist/: deploy/deb/build.sh. Needs a clean checkout.
deb: build
	@deploy/deb/build.sh
