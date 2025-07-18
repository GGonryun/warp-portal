# Root-level Makefile

.PHONY: all clean install uninstall

all:
	$(MAKE) -C nss
	$(MAKE) -C daemon

clean:
	$(MAKE) -C nss clean
	$(MAKE) -C daemon clean

install-deps:
	$(MAKE) -C nss test-deps
	$(MAKE) -C daemon test-deps

install: install-deps
	$(MAKE) -C nss install
	$(MAKE) -C daemon install

uninstall:
	$(MAKE) -C nss uninstall
	$(MAKE) -C daemon uninstall
