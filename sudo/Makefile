# Warp Portal Sudo Plugin Makefile

CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2 -std=c99
LDFLAGS = -shared
TARGET = warp_portal_sudo.so
SOURCE = warp_portal_sudo.c
OBJECT = $(SOURCE:.c=.o)

# Installation paths
PREFIX = /usr
LIBDIR = $(PREFIX)/libexec/sudo
CONFDIR = /etc/sudo.conf.d
LOGDIR = /var/log

# Plugin configuration
PLUGIN_CONF = warp_portal_sudo.conf

.PHONY: all clean install uninstall test setup

all: $(TARGET)

$(TARGET): $(OBJECT)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Built sudo plugin: $(TARGET)"

$(OBJECT): $(SOURCE)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECT) $(TARGET)
	@echo "Cleaned build artifacts"

install: $(TARGET) setup
	@echo "Installing Warp Portal sudo plugin..."
	
	# Create directories
	install -d $(LIBDIR)
	install -d $(CONFDIR)
	install -d $(LOGDIR)
	
	# Install plugin
	install -m 755 $(TARGET) $(LIBDIR)/$(TARGET)
	@echo "Installed plugin to $(LIBDIR)/$(TARGET)"
	
	# Install configuration
	@if [ ! -f $(CONFDIR)/$(PLUGIN_CONF) ]; then \
		echo "# Warp Portal Sudo Plugin Configuration" > $(CONFDIR)/$(PLUGIN_CONF); \
		echo "Plugin policy $(LIBDIR)/$(TARGET)" >> $(CONFDIR)/$(PLUGIN_CONF); \
		echo "Installed configuration to $(CONFDIR)/$(PLUGIN_CONF)"; \
	else \
		echo "Configuration file $(CONFDIR)/$(PLUGIN_CONF) already exists, skipping"; \
	fi
	
	# Set log file permissions
	touch $(LOGDIR)/warp_portal_sudo.log
	chmod 640 $(LOGDIR)/warp_portal_sudo.log
	chown root:adm $(LOGDIR)/warp_portal_sudo.log 2>/dev/null || true
	@echo "Created log file $(LOGDIR)/warp_portal_sudo.log"
	
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Ensure warp-portal daemon is running"
	@echo "2. Test with: sudo -V (should show plugin loaded)"
	@echo "3. Test sudo command execution"
	@echo "4. Check logs at $(LOGDIR)/warp_portal_sudo.log"

uninstall:
	@echo "Uninstalling Warp Portal sudo plugin..."
	rm -f $(LIBDIR)/$(TARGET)
	rm -f $(CONFDIR)/$(PLUGIN_CONF)
	@echo "Uninstalled plugin and configuration"
	@echo "Note: Log file $(LOGDIR)/warp_portal_sudo.log preserved"

setup:
	@echo "Setting up prerequisites..."
	
	# Check if sudo plugin API headers are available
	@if ! pkg-config --exists sudo; then \
		echo "Warning: sudo development headers not found"; \
		echo "Install with: apt-get install sudo-dev (Debian/Ubuntu) or yum install sudo-devel (RHEL/CentOS)"; \
	fi
	
	# Check if warp portal socket exists
	@if [ ! -S /run/warp_portal.sock ]; then \
		echo "Warning: Warp Portal daemon socket not found at /run/warp_portal.sock"; \
		echo "Ensure warp-portal daemon is running before using sudo plugin"; \
	else \
		echo "Found warp-portal daemon socket"; \
	fi
	
	# Check sudo.conf.d directory exists
	@if [ ! -d $(CONFDIR) ]; then \
		echo "Creating sudo configuration directory: $(CONFDIR)"; \
		mkdir -p $(CONFDIR); \
	fi

test: $(TARGET)
	@echo "Running basic tests..."
	
	# Test plugin loading
	@echo "Testing plugin compilation and basic structure..."
	@if nm $(TARGET) | grep -q "warp_portal_policy"; then \
		echo "✓ Plugin exports required symbol"; \
	else \
		echo "✗ Plugin missing required symbol"; \
		exit 1; \
	fi
	
	# Test daemon connectivity (if available)
	@echo "Testing daemon connectivity..."
	@if [ -S /run/warp_portal.sock ]; then \
		echo "✓ Daemon socket exists"; \
	else \
		echo "⚠ Daemon socket not found (daemon may not be running)"; \
	fi
	
	@echo "Basic tests completed"

# Development targets
debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

# Show plugin information
info:
	@echo "Warp Portal Sudo Plugin Build Information"
	@echo "========================================"
	@echo "Source: $(SOURCE)"
	@echo "Target: $(TARGET)"
	@echo "Install path: $(LIBDIR)/$(TARGET)"
	@echo "Config path: $(CONFDIR)/$(PLUGIN_CONF)"
	@echo "Log file: $(LOGDIR)/warp_portal_sudo.log"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"

# Check sudo configuration
check-config:
	@echo "Checking sudo configuration..."
	@if [ -f /etc/sudo.conf ]; then \
		echo "Main sudo.conf exists"; \
		if grep -q "Plugin.*policy.*warp_portal_sudo" /etc/sudo.conf; then \
			echo "✓ Warp Portal plugin configured in main sudo.conf"; \
		fi; \
	fi
	@if [ -d $(CONFDIR) ]; then \
		echo "Plugin config directory exists"; \
		if [ -f $(CONFDIR)/$(PLUGIN_CONF) ]; then \
			echo "✓ Plugin configuration file exists"; \
			cat $(CONFDIR)/$(PLUGIN_CONF); \
		fi; \
	fi

# Development help
help:
	@echo "Warp Portal Sudo Plugin Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the plugin (default)"
	@echo "  install    - Install plugin and configuration"
	@echo "  uninstall  - Remove plugin and configuration"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run basic functionality tests"
	@echo "  setup      - Check prerequisites and setup"
	@echo "  debug      - Build with debug symbols"
	@echo "  info       - Show build information"
	@echo "  check-config - Check sudo configuration"
	@echo "  help       - Show this help"