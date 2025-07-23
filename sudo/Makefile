# Warp Portal Sudo Plugin Makefile

CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2 -std=c99
LDFLAGS = -shared
TARGET = sudo_socket.so
SOURCE = sudo_socket.c
OBJECT = $(SOURCE:.c=.o)

# Installation paths
PREFIX = /usr
LIBDIR = $(PREFIX)/libexec/sudo
CONFDIR = /etc/sudo.conf.d
LOGDIR = /var/log

# Plugin configuration
PLUGIN_CONF = sudo_socket.conf

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
	
	# Install configuration - Try direct sudo.conf first (recommended)
	@echo "Configuring sudo plugin..."
	@if [ -w /etc/sudo.conf ] || [ ! -f /etc/sudo.conf ]; then \
		if ! grep -q "Plugin policy $(LIBDIR)/$(TARGET)" /etc/sudo.conf 2>/dev/null; then \
			echo "Plugin policy $(LIBDIR)/$(TARGET)" >> /etc/sudo.conf; \
			echo "Added plugin configuration to /etc/sudo.conf"; \
		else \
			echo "Plugin already configured in /etc/sudo.conf"; \
		fi; \
	elif [ -d $(CONFDIR) ]; then \
		if [ ! -f $(CONFDIR)/$(PLUGIN_CONF) ]; then \
			echo "# Sudo Socket Plugin Configuration" > $(CONFDIR)/$(PLUGIN_CONF); \
			echo "Plugin policy $(LIBDIR)/$(TARGET)" >> $(CONFDIR)/$(PLUGIN_CONF); \
			echo "Installed configuration to $(CONFDIR)/$(PLUGIN_CONF)"; \
			echo "WARNING: Using sudo.conf.d method - verify your sudo version supports this"; \
		else \
			echo "Configuration file $(CONFDIR)/$(PLUGIN_CONF) already exists"; \
		fi; \
	else \
		echo "ERROR: Cannot write to /etc/sudo.conf and $(CONFDIR) doesn't exist"; \
		echo "Please manually add: Plugin policy $(LIBDIR)/$(TARGET) to /etc/sudo.conf"; \
		exit 1; \
	fi
	
	# Set log file permissions
	touch $(LOGDIR)/sudo_socket.log
	chmod 640 $(LOGDIR)/sudo_socket.log
	chown root:adm $(LOGDIR)/sudo_socket.log 2>/dev/null || true
	@echo "Created log file $(LOGDIR)/sudo_socket.log"
	
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Ensure warp-portal daemon is running"
	@echo "2. Test with: sudo -V (should show plugin loaded)"
	@echo "3. Test sudo command execution"
	@echo "4. Check logs at $(LOGDIR)/sudo_socket.log"

uninstall:
	@echo "Uninstalling Sudo Socket plugin..."
	rm -f $(LIBDIR)/$(TARGET)
	
	# Remove from main sudo.conf if present
	@if [ -f /etc/sudo.conf ]; then \
		if grep -q "Plugin policy $(LIBDIR)/$(TARGET)" /etc/sudo.conf; then \
			grep -v "Plugin policy $(LIBDIR)/$(TARGET)" /etc/sudo.conf > /tmp/sudo.conf.tmp; \
			mv /tmp/sudo.conf.tmp /etc/sudo.conf; \
			echo "Removed plugin configuration from /etc/sudo.conf"; \
		fi; \
	fi
	
	# Remove sudo.conf.d file if present
	rm -f $(CONFDIR)/$(PLUGIN_CONF)
	
	@echo "Uninstalled plugin and configuration"
	@echo "Note: Log file $(LOGDIR)/sudo_socket.log preserved"

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
	@if nm $(TARGET) | grep -q "sudo_socket_policy"; then \
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
	@echo "Log file: $(LOGDIR)/sudo_socket.log"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"

# Check sudo configuration
check-config:
	@echo "Checking sudo configuration methods..."
	@echo ""
	
	# Check Method 1: Direct sudo.conf
	@echo "Method 1: Direct /etc/sudo.conf configuration"
	@if [ -f /etc/sudo.conf ]; then \
		echo "✓ /etc/sudo.conf exists"; \
		if grep -q "Plugin.*policy.*$(LIBDIR)/$(TARGET)" /etc/sudo.conf; then \
			echo "✓ Sudo Socket plugin configured in main sudo.conf"; \
			echo "  Line: $$(grep 'Plugin.*policy.*$(LIBDIR)/$(TARGET)' /etc/sudo.conf)"; \
		else \
			echo "✗ Plugin not found in /etc/sudo.conf"; \
		fi; \
	else \
		echo "✗ /etc/sudo.conf does not exist"; \
	fi
	@echo ""
	
	# Check Method 2: sudo.conf.d
	@echo "Method 2: /etc/sudo.conf.d/ configuration"
	@if [ -d $(CONFDIR) ]; then \
		echo "✓ $(CONFDIR) directory exists"; \
		if [ -f $(CONFDIR)/$(PLUGIN_CONF) ]; then \
			echo "✓ Plugin configuration file exists: $(CONFDIR)/$(PLUGIN_CONF)"; \
			echo "  Content:"; \
			sed 's/^/    /' $(CONFDIR)/$(PLUGIN_CONF); \
		else \
			echo "✗ Plugin configuration file not found: $(CONFDIR)/$(PLUGIN_CONF)"; \
		fi; \
	else \
		echo "✗ $(CONFDIR) directory does not exist"; \
	fi
	@echo ""
	
	# Test plugin loading
	@echo "Plugin loading test:"
	@if command -v sudo >/dev/null 2>&1; then \
		if sudo -V 2>/dev/null | grep -q -i "sudo_socket\|$(TARGET)"; then \
			echo "✓ Plugin appears to be loaded by sudo"; \
		else \
			echo "✗ Plugin not detected in sudo -V output"; \
			echo "  Run 'sudo -V | grep -i plugin' to see loaded plugins"; \
		fi; \
	else \
		echo "✗ sudo command not found"; \
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