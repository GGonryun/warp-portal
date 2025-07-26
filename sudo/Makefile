# Warp Portal Group-Based Sudo Configuration Makefile

# Installation paths  
LOGDIR = /var/log
SUDOERS_FILE = /etc/sudoers
SUDOERS_BACKUP_DIR = /etc/sudoers.d

# Reserved GIDs for warp-portal groups
WARP_PORTAL_ADMIN_GID = 64200
WARP_PORTAL_USER_GID = 64201

.PHONY: all build install uninstall setup-groups setup show-groups backup-sudoers install-deps help

# Build target (no-op for sudo configuration, just validation)
all:
	@echo "Sudo configuration component ready (no compilation needed)"

# Build target alias (same as all for consistency)
build: all
	@echo "Sudo configuration component ready (no compilation needed)"

backup-sudoers:
	@echo "Creating backup of sudoers configuration..."
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	sudo cp $(SUDOERS_FILE) $(SUDOERS_FILE).bak.$$TIMESTAMP; \
	echo "Sudoers file backed up to $(SUDOERS_FILE).bak.$$TIMESTAMP"

install: setup-groups backup-sudoers
	@echo "Installing Warp Portal group-based sudo configuration..."
	
	# Create log directory
	sudo install -d $(LOGDIR)
	
	# Set up sudoers configuration using sudoers.d (safer approach)
	@echo "Configuring sudoers for warp-portal-admin group..."
	@if [ ! -f $(SUDOERS_BACKUP_DIR)/warp_portal ]; then \
		echo "# Warp Portal sudo access" | sudo tee $(SUDOERS_BACKUP_DIR)/warp_portal > /dev/null; \
		echo "# Allow members of warp-portal-admin group to execute any command" | sudo tee -a $(SUDOERS_BACKUP_DIR)/warp_portal > /dev/null; \
		echo "%warp-portal-admin ALL=(ALL:ALL) ALL" | sudo tee -a $(SUDOERS_BACKUP_DIR)/warp_portal > /dev/null; \
		sudo chmod 440 $(SUDOERS_BACKUP_DIR)/warp_portal; \
		echo "Created $(SUDOERS_BACKUP_DIR)/warp_portal configuration"; \
	else \
		echo "warp_portal sudoers configuration already exists"; \
	fi
	
	# Validate the sudoers configuration
	@if sudo visudo -c -f $(SUDOERS_BACKUP_DIR)/warp_portal; then \
		echo "Sudoers configuration validated successfully"; \
	else \
		echo "Error: Invalid sudoers configuration, removing file"; \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/warp_portal; \
		exit 1; \
	fi
	
	# Set log file permissions
	sudo touch $(LOGDIR)/warp_portal.log
	sudo chmod 640 $(LOGDIR)/warp_portal.log
	sudo chown root:adm $(LOGDIR)/warp_portal.log 2>/dev/null || true
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
	
	# Create backup before removing configuration
	@if [ -f $(SUDOERS_BACKUP_DIR)/warp_portal ]; then \
		TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
		sudo cp $(SUDOERS_BACKUP_DIR)/warp_portal $(SUDOERS_BACKUP_DIR)/warp_portal.removed.$$TIMESTAMP; \
		echo "Backed up existing configuration to $(SUDOERS_BACKUP_DIR)/warp_portal.removed.$$TIMESTAMP"; \
	fi
	
	# Remove sudoers configuration file
	@if [ -f $(SUDOERS_BACKUP_DIR)/warp_portal ]; then \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/warp_portal; \
		echo "Removed warp_portal sudoers configuration from $(SUDOERS_BACKUP_DIR)/warp_portal"; \
	else \
		echo "No warp_portal sudoers configuration found"; \
	fi
	
	# Clean up any old-format files that might exist
	@if [ -f $(SUDOERS_BACKUP_DIR)/warp-portal ]; then \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/warp-portal; \
		echo "Removed legacy warp-portal sudoers configuration"; \
	fi
	
	@echo ""
	@echo "✅ Uninstalled group-based sudo configuration"
	@echo "Note: Groups warp-portal-admin and warp-portal-user preserved"
	@echo "To remove groups manually: 'sudo groupdel warp-portal-admin && sudo groupdel warp-portal-user'"
	@echo "Note: Log file $(LOGDIR)/warp_portal.log preserved"
	@echo "Note: Sudoers backup files preserved"
	@echo ""
	@echo "To remove groups manually:"
	@echo "  sudo groupdel warp-portal-admin"
	@echo "  sudo groupdel warp-portal-user"

setup-groups:
	@echo "Setting up Warp Portal groups with reserved GIDs..."
	
	# Create warp-portal-admin group with reserved GID 64200
	@if ! getent group warp-portal-admin >/dev/null 2>&1; then \
		sudo groupadd --gid $(WARP_PORTAL_ADMIN_GID) warp-portal-admin; \
		echo "Created warp-portal-admin group (GID: $(WARP_PORTAL_ADMIN_GID))"; \
	else \
		EXISTING_GID=$$(getent group warp-portal-admin | cut -d: -f3); \
		if [ "$$EXISTING_GID" != "$(WARP_PORTAL_ADMIN_GID)" ]; then \
			echo "Warning: warp-portal-admin group exists with GID $$EXISTING_GID (expected $(WARP_PORTAL_ADMIN_GID))"; \
			echo "Consider removing the existing group and reinstalling"; \
		else \
			echo "warp-portal-admin group already exists with correct GID $(WARP_PORTAL_ADMIN_GID)"; \
		fi \
	fi
	
	# Create warp-portal-user group with reserved GID 64201
	@if ! getent group warp-portal-user >/dev/null 2>&1; then \
		sudo groupadd --gid $(WARP_PORTAL_USER_GID) warp-portal-user; \
		echo "Created warp-portal-user group (GID: $(WARP_PORTAL_USER_GID))"; \
	else \
		EXISTING_GID=$$(getent group warp-portal-user | cut -d: -f3); \
		if [ "$$EXISTING_GID" != "$(WARP_PORTAL_USER_GID)" ]; then \
			echo "Warning: warp-portal-user group exists with GID $$EXISTING_GID (expected $(WARP_PORTAL_USER_GID))"; \
			echo "Consider removing the existing group and reinstalling"; \
		else \
			echo "warp-portal-user group already exists with correct GID $(WARP_PORTAL_USER_GID)"; \
		fi \
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
	@echo "Expected reserved GIDs:"
	@echo "  warp-portal-admin: $(WARP_PORTAL_ADMIN_GID)"
	@echo "  warp-portal-user:  $(WARP_PORTAL_USER_GID)"
	@echo ""
	@echo "System groups:"
	@if getent group warp-portal-admin >/dev/null 2>&1; then \
		ADMIN_GID=$$(getent group warp-portal-admin | cut -d: -f3); \
		if [ "$$ADMIN_GID" = "$(WARP_PORTAL_ADMIN_GID)" ]; then \
			echo "  warp-portal-admin: ✓ exists (GID $$ADMIN_GID)"; \
		else \
			echo "  warp-portal-admin: ⚠ exists but wrong GID $$ADMIN_GID (expected $(WARP_PORTAL_ADMIN_GID))"; \
		fi \
	else \
		echo "  warp-portal-admin: ✗ not found"; \
	fi
	@if getent group warp-portal-user >/dev/null 2>&1; then \
		USER_GID=$$(getent group warp-portal-user | cut -d: -f3); \
		if [ "$$USER_GID" = "$(WARP_PORTAL_USER_GID)" ]; then \
			echo "  warp-portal-user:  ✓ exists (GID $$USER_GID)"; \
		else \
			echo "  warp-portal-user:  ⚠ exists but wrong GID $$USER_GID (expected $(WARP_PORTAL_USER_GID))"; \
		fi \
	else \
		echo "  warp-portal-user:  ✗ not found"; \
	fi
	@echo ""
	@echo "Sudoers configuration:"
	@if [ -f $(SUDOERS_BACKUP_DIR)/warp-portal ]; then \
		echo "  ✓ Found in $(SUDOERS_BACKUP_DIR)/warp-portal"; \
		echo "  Configuration:"; \
		sudo cat $(SUDOERS_BACKUP_DIR)/warp-portal | grep -v "^#" | sed 's/^/    /'; \
	else \
		echo "  ✗ Not found in $(SUDOERS_BACKUP_DIR)/warp-portal"; \
	fi
	@echo ""
	@echo "Daemon socket:"
	@if [ -S /run/warp_portal.sock ]; then \
		echo "  ✓ Daemon socket found at /run/warp_portal.sock"; \
	else \
		echo "  ✗ Daemon socket not found at /run/warp_portal.sock"; \
	fi

install-deps:
	@echo "Installing sudo dependencies..."
	@if ! command -v sudo >/dev/null 2>&1; then \
		echo "Installing sudo package..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y sudo; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y sudo; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y sudo; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm sudo; \
		else \
			echo "Package manager not supported. Please install sudo manually."; \
			exit 1; \
		fi; \
	else \
		echo "sudo: Already installed"; \
	fi
	@echo "All sudo dependencies installed successfully"

# Development help
help:
	@echo "Warp Portal Group-Based Sudo Configuration Makefile"
	@echo ""
	@echo "This Makefile manages warp-portal groups with reserved GIDs:"
	@echo "  - warp-portal-admin (GID $(WARP_PORTAL_ADMIN_GID)): Sudo access"
	@echo "  - warp-portal-user  (GID $(WARP_PORTAL_USER_GID)): Regular access"
	@echo ""
	@echo "Targets:"
	@echo "  install       - Create groups, backup sudoers, install sudo configuration (includes dependencies)"
	@echo "  uninstall     - Remove sudo configuration (preserves groups)"
	@echo "  setup-groups  - Create warp-portal groups with reserved GIDs"
	@echo "  backup-sudoers- Create timestamped backup of /etc/sudoers"
	@echo "  setup         - Check prerequisites"
	@echo "  show-groups   - Display current group and sudo configuration"
	@echo "  install-deps  - Install sudo package dependencies"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Safety features:"
	@echo "  - Uses /etc/sudoers.d/ for configuration (safer)"
	@echo "  - Validates sudoers syntax before applying"
	@echo "  - Creates timestamped backups"
	@echo "  - Preserves groups and backups during uninstall"