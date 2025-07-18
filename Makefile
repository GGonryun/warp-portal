# Root-level Makefile

.PHONY: all clean install uninstall

all:
	$(MAKE) -C nss
	$(MAKE) -C daemon

clean:
	$(MAKE) -C nss clean
	$(MAKE) -C daemon clean

test-deps:
	$(MAKE) -C nss test-deps
	$(MAKE) -C daemon test-deps

install-deps: install-deps
	$(MAKE) -C nss install-deps
	$(MAKE) -C daemon install-deps

uninstall:
	$(MAKE) -C nss uninstall
	$(MAKE) -C daemon uninstall
