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

.PHONY: all build clean install uninstall install-deps install-samples test

all: $(TARGET)

# Install development dependencies
install-deps:
	@echo "Installing NSS cache module dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		apt-get update && apt-get install -y build-essential libc6-dev; \
	elif command -v yum >/dev/null 2>&1; then \
		yum install -y gcc glibc-devel; \
	elif command -v dnf >/dev/null 2>&1; then \
		dnf install -y gcc glibc-devel; \
	elif command -v pacman >/dev/null 2>&1; then \
		pacman -S --noconfirm gcc glibc; \
	else \
		echo "Package manager not found. Please install build-essential/gcc and libc6-dev/glibc-devel manually"; \
		exit 1; \
	fi
	@echo "Dependencies installed successfully"

# Build target (alias for all)
build: $(TARGET)

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