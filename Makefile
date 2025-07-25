# Root-level Makefile for Warp Portal
# This orchestrates installation across all components

.PHONY: all clean install install-deps uninstall backup-check build status help

# Default target builds all components
all: build

# Build all components
build: install-deps
	@echo "Building all Warp Portal components..."
	$(MAKE) -C daemon
	$(MAKE) -C nss
	$(MAKE) -C pam
	$(MAKE) -C sshd
	$(MAKE) -C sudo
	$(MAKE) -C cli

# Clean all components
clean:
	@echo "Cleaning all Warp Portal components..."
	$(MAKE) -C daemon clean
	$(MAKE) -C nss clean
	$(MAKE) -C pam clean
	$(MAKE) -C sshd clean
	$(MAKE) -C sudo clean
	$(MAKE) -C cli clean

# Install dependencies for all components
install-deps:
	@echo "Installing dependencies for all Warp Portal components..."
	$(MAKE) -C daemon install-deps
	$(MAKE) -C nss install-deps
	$(MAKE) -C pam install-deps
	$(MAKE) -C sshd install-deps
	$(MAKE) -C sudo install-deps
	$(MAKE) -C cli deps

# Check if running as root (required for system-wide installation)
root-check:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Installation must be run as root (use sudo make install)"; \
		exit 1; \
	fi

# Complete installation with backups and configuration
install: root-check install-deps build
	@echo "=========================================="
	@echo "Installing Warp Portal System Components"
	@echo "=========================================="
	@echo "This will:"
	@echo "  - Install all required dependencies automatically"
	@echo "  - Build and install all binaries and libraries"
	@echo "  - Create automatic backups of system files"
	@echo "  - Configure system components (NSS, systemd)"
	@echo "  - Set up groups and permissions"
	@echo "  - Install service files"
	@echo ""
	@echo "Components to install:"
	@echo "  • Daemon (Go binary + systemd service)"
	@echo "  • NSS module (system library + nsswitch.conf)"
	@echo "  • PAM module (authentication library)"
	@echo "  • SSH module (authorized keys handler)"
	@echo "  • Sudo configuration (groups + sudoers)"
	@echo "  • CLI tool (portal management command)"
	@echo ""
	@read -p "Continue with installation? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo ""
	@echo "[1/6] Installing daemon..."
	@if $(MAKE) -C daemon install; then \
		echo "✓ Daemon installation completed"; \
	else \
		echo "✗ Daemon installation failed"; exit 1; \
	fi
	@echo ""
	@echo "[2/6] Installing NSS module..."
	@if $(MAKE) -C nss install; then \
		echo "✓ NSS module installation completed"; \
	else \
		echo "✗ NSS module installation failed"; exit 1; \
	fi
	@echo ""
	@echo "[3/6] Installing PAM module..."
	@if $(MAKE) -C pam install; then \
		echo "✓ PAM module installation completed"; \
	else \
		echo "✗ PAM module installation failed"; exit 1; \
	fi
	@echo ""
	@echo "[4/6] Installing SSH module..."
	@if $(MAKE) -C sshd install; then \
		echo "✓ SSH module installation completed"; \
	else \
		echo "✗ SSH module installation failed"; exit 1; \
	fi
	@echo ""
	@echo "[5/6] Installing sudo configuration..."
	@if $(MAKE) -C sudo install; then \
		echo "✓ Sudo configuration completed"; \
	else \
		echo "✗ Sudo configuration failed"; exit 1; \
	fi
	@echo ""
	@echo "[6/6] Installing CLI tool..."
	@if $(MAKE) -C cli install; then \
		echo "✓ CLI tool installation completed"; \
	else \
		echo "✗ CLI tool installation failed"; exit 1; \
	fi
	@echo ""
	@echo "=========================================="
	@echo "✓ Warp Portal installation complete!"
	@echo "=========================================="
	@echo ""
	@echo "📋 Post-installation checklist:"
	@echo "  1. ⚙️  Configure /etc/warp_portal/config.yaml with your settings"
	@echo "  2. 🔐 Configure SSH (run 'make -C sshd configure-ssh')"
	@echo "  3. 🔒 Configure PAM (run 'make -C pam configure-pam')"
	@echo "  4. 📝 Generate registration code: warpportal register"
	@echo "  5. 🚀 Start daemon: systemctl start warp_portal_daemon"
	@echo "  6. ✅ Enable auto-start: systemctl enable warp_portal_daemon"
	@echo "  7. 👥 Add users to warp-portal groups as needed"
	@echo ""
	@echo "🛡️  All system files have been automatically backed up with timestamps"
	@echo "📊 Check status: warpportal status (or make status)"
	@echo "🔧 CLI commands: warpportal --help"
	@echo ""

# Uninstall all components (restores backups)
uninstall: root-check
	@echo "=========================================="
	@echo "Uninstalling Warp Portal System Components"
	@echo "=========================================="
	@echo "This will:"
	@echo "  - Remove all installed binaries and libraries"
	@echo "  - Restore configuration backups"
	@echo "  - Stop and disable services"
	@echo ""
	@read -p "Continue? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo ""
	$(MAKE) -C cli uninstall
	$(MAKE) -C sudo uninstall
	$(MAKE) -C sshd uninstall
	$(MAKE) -C pam uninstall
	$(MAKE) -C nss uninstall
	$(MAKE) -C daemon uninstall
	@echo ""
	@echo "=========================================="
	@echo "Warp Portal uninstallation complete!"
	@echo "=========================================="

# Check installation status across all components
status:
	@echo "=========================================="
	@echo "Warp Portal System Status"
	@echo "=========================================="
	@echo ""
	@echo "🔧 Daemon Status:"
	@$(MAKE) -C daemon status 2>/dev/null || echo "  Status check failed"
	@echo ""
	@echo "🔗 NSS Module Status:"
	@if [ -f nss/libnss_socket.so.2 ]; then \
		echo "  Binary: ✓ Built"; \
	else \
		echo "  Binary: ✗ Not built"; \
	fi
	@if [ -f /usr/lib/x86_64-linux-gnu/libnss_socket.so.2 ] || [ -f /usr/lib/libnss_socket.so.2 ] || [ -f /lib/libnss_socket.so.2 ]; then \
		echo "  Installation: ✓ Installed"; \
	else \
		echo "  Installation: ✗ Not installed"; \
	fi
	@if grep -q "socket" /etc/nsswitch.conf 2>/dev/null; then \
		echo "  NSSwitch config: ✓ Configured"; \
	else \
		echo "  NSSwitch config: ✗ Not configured"; \
	fi
	@echo ""
	@echo "🔐 PAM Module Status:"
	@$(MAKE) -C pam status 2>/dev/null || echo "  Status check failed"
	@echo ""
	@echo "🔑 SSH Module Status:"
	@$(MAKE) -C sshd status 2>/dev/null || echo "  Status check failed"
	@echo ""
	@echo "👥 Sudo Configuration Status:"
	@$(MAKE) -C sudo show-groups 2>/dev/null || echo "  Status check failed"
	@echo ""
	@echo "🔌 Service Status:"
	@if systemctl is-active warp_portal_daemon.service >/dev/null 2>&1; then \
		echo "  Daemon service: ✓ Running"; \
	elif systemctl is-enabled warp_portal_daemon.service >/dev/null 2>&1; then \
		echo "  Daemon service: ⚠ Installed but stopped"; \
	else \
		echo "  Daemon service: ✗ Not installed"; \
	fi
	@if [ -S /run/warp_portal.sock ]; then \
		echo "  Socket: ✓ Active"; \
	else \
		echo "  Socket: ✗ Not found"; \
	fi
	@echo ""

# Show help information
help:
	@echo "Warp Portal System Installation"
	@echo "==============================="
	@echo ""
	@echo "Available targets:"
	@echo "  all           - Build all components"
	@echo "  build         - Build all components"
	@echo "  install       - Complete system installation (includes dependencies)"
	@echo "  install-deps  - Install dependencies for all components"
	@echo "  uninstall     - Remove all components and restore backups"
	@echo "  status        - Check installation status of all components"
	@echo "  clean         - Clean all build artifacts"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "⚠️  Installation requires root privileges: sudo make install"
	@echo ""
	@echo "✨ Features:"
	@echo "  • Automatic dependency installation"
	@echo "  • Automatic system file backups"
	@echo "  • Component-by-component error handling"
	@echo "  • Comprehensive status reporting"
	@echo "  • Unified CLI tool for management"
	@echo ""
