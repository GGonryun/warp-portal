# Warp Portal Group-Based Sudo Configuration Makefile

# Installation paths  
LOGDIR = /var/log

.PHONY: install uninstall setup-groups setup show-groups help

install: setup-groups
	@echo "Installing Warp Portal group-based sudo configuration..."
	
	# Create log directory
	install -d $(LOGDIR)
	
	# Set up sudoers configuration
	@echo "Configuring sudoers for warp-portal-admin group..."
	@if ! grep -q "^%warp-portal-admin" /etc/sudoers 2>/dev/null; then \
		echo "" >> /etc/sudoers; \
		echo "# Warp Portal sudo access" >> /etc/sudoers; \
		echo "%warp-portal-admin ALL=(ALL:ALL) ALL" >> /etc/sudoers; \
		echo "Added warp-portal-admin group to sudoers"; \
	else \
		echo "warp-portal-admin group already configured in sudoers"; \
	fi
	
	# Set log file permissions
	touch $(LOGDIR)/warp_portal.log
	chmod 640 $(LOGDIR)/warp_portal.log
	chown root:adm $(LOGDIR)/warp_portal.log 2>/dev/null || true
	@echo "Created log file $(LOGDIR)/warp_portal.log"
	
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Ensure warp-portal daemon is running"
	@echo "2. Add users to warp-portal-admin or warp-portal-user groups"
	@echo "3. Test sudo access for users in warp-portal-admin group"
	@echo "4. Check logs at $(LOGDIR)/warp_portal.log"
	@echo ""
	@echo "To add users to groups manually:"
	@echo "  sudo usermod -a -G warp-portal-admin username    # For sudo access"
	@echo "  sudo usermod -a -G warp-portal-user username     # For regular access"

uninstall:
	@echo "Uninstalling Warp Portal group-based sudo configuration..."
	
	# Remove sudoers configuration
	@if grep -q "^%warp-portal-admin" /etc/sudoers 2>/dev/null; then \
		grep -v "^%warp-portal-admin\|^# Warp Portal sudo access" /etc/sudoers > /tmp/sudoers.tmp; \
		visudo -c -f /tmp/sudoers.tmp && mv /tmp/sudoers.tmp /etc/sudoers; \
		echo "Removed warp-portal-admin from sudoers"; \
	else \
		echo "No warp-portal-admin configuration found in sudoers"; \
	fi
	
	@echo ""
	@echo "Uninstalled group-based sudo configuration"
	@echo "Note: Groups warp-portal-admin and warp-portal-user preserved"
	@echo "Note: Log file $(LOGDIR)/warp_portal.log preserved"
	@echo ""
	@echo "To remove groups manually:"
	@echo "  sudo groupdel warp-portal-admin"
	@echo "  sudo groupdel warp-portal-user"

setup-groups:
	@echo "Setting up Warp Portal groups..."
	
	# Create warp-portal-admin group (let system assign GID)
	@if ! getent group warp-portal-admin >/dev/null 2>&1; then \
		groupadd warp-portal-admin; \
		ADMIN_GID=$$(getent group warp-portal-admin | cut -d: -f3); \
		echo "Created warp-portal-admin group with system-assigned GID $$ADMIN_GID"; \
	else \
		ADMIN_GID=$$(getent group warp-portal-admin | cut -d: -f3); \
		echo "warp-portal-admin group already exists with GID $$ADMIN_GID"; \
	fi
	
	# Create warp-portal-user group (let system assign GID)
	@if ! getent group warp-portal-user >/dev/null 2>&1; then \
		groupadd warp-portal-user; \
		USER_GID=$$(getent group warp-portal-user | cut -d: -f3); \
		echo "Created warp-portal-user group with system-assigned GID $$USER_GID"; \
	else \
		USER_GID=$$(getent group warp-portal-user | cut -d: -f3); \
		echo "warp-portal-user group already exists with GID $$USER_GID"; \
	fi
	
	# Check if warp portal socket exists
	@if [ ! -S /run/warp_portal.sock ]; then \
		echo "Warning: Warp Portal daemon socket not found at /run/warp_portal.sock"; \
		echo "Ensure warp-portal daemon is running"; \
	else \
		echo "Found warp-portal daemon socket"; \
	fi

setup:
	@echo "Setting up prerequisites..."
	
	# Check if sudo is available
	@if ! command -v sudo >/dev/null 2>&1; then \
		echo "Error: sudo not found"; \
		exit 1; \
	fi
	
	@echo "Prerequisites check complete"

# Show group configuration information
show-groups:
	@echo "Warp Portal Group Configuration"
	@echo "==============================="
	@echo ""
	@echo "System groups:"
	@if getent group warp-portal-admin >/dev/null 2>&1; then \
		ADMIN_GID=$$(getent group warp-portal-admin | cut -d: -f3); \
		echo "  warp-portal-admin: exists (GID $$ADMIN_GID)"; \
	else \
		echo "  warp-portal-admin: not found"; \
	fi
	@if getent group warp-portal-user >/dev/null 2>&1; then \
		USER_GID=$$(getent group warp-portal-user | cut -d: -f3); \
		echo "  warp-portal-user: exists (GID $$USER_GID)"; \
	else \
		echo "  warp-portal-user: not found"; \
	fi
	@echo ""
	@echo "Sudoers configuration:"
	@grep warp-portal-admin /etc/sudoers 2>/dev/null && echo "  Found in /etc/sudoers" || echo "  Not found in /etc/sudoers"

# Development help
help:
	@echo "Warp Portal Group-Based Sudo Configuration Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install       - Install group-based sudo configuration"
	@echo "  uninstall     - Remove group-based sudo configuration"
	@echo "  setup-groups  - Create warp-portal groups with config GIDs"
	@echo "  setup         - Check prerequisites"
	@echo "  show-groups   - Display current group configuration"
	@echo "  help          - Show this help"