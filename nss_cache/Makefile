CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared
LDFLAGS = -shared
TARGET = libnss_cache.so.2
SOURCES = nss_cache.c
OBJECTS = $(SOURCES:.c=.o)

# Installation paths
PREFIX = /usr
LIBDIR = $(PREFIX)/lib/x86_64-linux-gnu
CACHE_DIR = /var/cache/warp_portal

.PHONY: all clean install uninstall install-samples test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	install -d $(LIBDIR)
	install -m 755 $(TARGET) $(LIBDIR)/
	install -d $(CACHE_DIR)
	chmod 755 $(CACHE_DIR)
	@echo "NSS cache module installed successfully"
	@echo "Add 'nss_cache' to /etc/nsswitch.conf entries as needed"

uninstall:
	rm -f $(LIBDIR)/$(TARGET)
	@echo "NSS cache module uninstalled"

# Create cache directory for development/testing
cache-dir:
	mkdir -p $(CACHE_DIR)
	chmod 755 $(CACHE_DIR)

# Install sample cache files for testing
install-samples: cache-dir
	install -m 644 samples/passwd.cache $(CACHE_DIR)/
	install -m 644 samples/group.cache $(CACHE_DIR)/
	@echo "Sample cache files installed to $(CACHE_DIR)"
	@echo "Configure /etc/nsswitch.conf to add 'nss_cache' for testing"

# Test the NSS cache module with sample data
test: install-samples
	@echo "Testing NSS cache module..."
	@echo "Testing user lookups:"
	@getent passwd miguel || echo "  ✗ miguel lookup failed"
	@getent passwd alice || echo "  ✗ alice lookup failed"
	@getent passwd admin || echo "  ✗ admin lookup failed"
	@echo "Testing group lookups:"
	@getent group developers || echo "  ✗ developers lookup failed"
	@getent group warp-portal-admin || echo "  ✗ warp-portal-admin lookup failed"
	@echo "Testing ID lookups:"
	@getent passwd 2000 || echo "  ✗ UID 2000 lookup failed"
	@getent group 4000 || echo "  ✗ GID 4000 lookup failed"
	@echo "Test completed. Check /etc/nsswitch.conf if lookups failed."