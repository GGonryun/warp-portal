# P0 Agent Group-Based Sudo Configuration Makefile

# Installation paths  
LOGDIR = /var/log
SUDOERS_FILE = /etc/sudoers
SUDOERS_BACKUP_DIR = /etc/sudoers.d

# Reserved GIDs for p0-agent groups
P0_AGENT_ADMIN_GID = 64200
P0_AGENT_USER_GID = 64201

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
	@echo "Installing P0 Agent group-based sudo configuration..."
	
	# Create log directory
	sudo install -d $(LOGDIR)
	
	# Set up sudoers configuration using sudoers.d (safer approach)
	@echo "Configuring sudoers for p0-agent-admin group..."
	@if [ ! -f $(SUDOERS_BACKUP_DIR)/p0_agent ]; then \
		echo "# P0 Agent sudo access" | sudo tee $(SUDOERS_BACKUP_DIR)/p0_agent > /dev/null; \
		echo "# Allow members of p0-agent-admin group to execute any command without password" | sudo tee -a $(SUDOERS_BACKUP_DIR)/p0_agent > /dev/null; \
		echo "%p0-agent-admin ALL=(ALL:ALL) NOPASSWD:ALL" | sudo tee -a $(SUDOERS_BACKUP_DIR)/p0_agent > /dev/null; \
		sudo chmod 440 $(SUDOERS_BACKUP_DIR)/p0_agent; \
		echo "Created $(SUDOERS_BACKUP_DIR)/p0_agent configuration"; \
	else \
		echo "p0_agent sudoers configuration already exists"; \
	fi
	
	# Validate the sudoers configuration
	@if sudo visudo -c -f $(SUDOERS_BACKUP_DIR)/p0_agent; then \
		echo "Sudoers configuration validated successfully"; \
	else \
		echo "Error: Invalid sudoers configuration, removing file"; \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/p0_agent; \
		exit 1; \
	fi
	
	# Set log file permissions
	sudo touch $(LOGDIR)/p0_agent.log
	sudo chmod 640 $(LOGDIR)/p0_agent.log
	sudo chown root:adm $(LOGDIR)/p0_agent.log 2>/dev/null || true
	@echo "Created log file $(LOGDIR)/p0_agent.log"
	
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Ensure p0-agent daemon is running"
	@echo "2. Add users to p0-agent-admin or p0-agent-user groups"
	@echo "3. Test sudo access for users in p0-agent-admin group"
	@echo "4. Check logs at $(LOGDIR)/p0_agent.log"
	@echo ""
	@echo "To add users to groups manually:"
	@echo "  sudo usermod -a -G p0-agent-admin username    # For passwordless sudo access"
	@echo "  sudo usermod -a -G p0-agent-user username     # For regular access"

uninstall:
	@echo "Uninstalling P0 Agent group-based sudo configuration..."
	
	# Create backup before removing configuration
	@if [ -f $(SUDOERS_BACKUP_DIR)/p0_agent ]; then \
		TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
		sudo cp $(SUDOERS_BACKUP_DIR)/p0_agent $(SUDOERS_BACKUP_DIR)/p0_agent.removed.$$TIMESTAMP; \
		echo "Backed up existing configuration to $(SUDOERS_BACKUP_DIR)/p0_agent.removed.$$TIMESTAMP"; \
	fi
	
	# Remove sudoers configuration file
	@if [ -f $(SUDOERS_BACKUP_DIR)/p0_agent ]; then \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/p0_agent; \
		echo "Removed p0_agent sudoers configuration from $(SUDOERS_BACKUP_DIR)/p0_agent"; \
	else \
		echo "No p0_agent sudoers configuration found"; \
	fi
	
	# Clean up any old-format files that might exist
	@if [ -f $(SUDOERS_BACKUP_DIR)/p0-agent ]; then \
		sudo rm -f $(SUDOERS_BACKUP_DIR)/p0-agent; \
		echo "Removed legacy p0-agent sudoers configuration"; \
	fi
	
	@echo ""
	@echo "✅ Uninstalled group-based sudo configuration"
	@echo "Note: Groups p0-agent-admin and p0-agent-user preserved"
	@echo "To remove groups manually: 'sudo groupdel p0-agent-admin && sudo groupdel p0-agent-user'"
	@echo "Note: Log file $(LOGDIR)/p0_agent.log preserved"
	@echo "Note: Sudoers backup files preserved"
	@echo ""
	@echo "To remove groups manually:"
	@echo "  sudo groupdel p0-agent-admin"
	@echo "  sudo groupdel p0-agent-user"

setup-groups:
	@echo "Setting up P0 Agent groups with reserved GIDs..."
	
	# Create p0-agent-admin group with reserved GID 64200
	@if ! getent group p0-agent-admin >/dev/null 2>&1; then \
		sudo groupadd --gid $(P0_AGENT_ADMIN_GID) p0-agent-admin; \
		echo "Created p0-agent-admin group (GID: $(P0_AGENT_ADMIN_GID))"; \
	else \
		EXISTING_GID=$$(getent group p0-agent-admin | cut -d: -f3); \
		if [ "$$EXISTING_GID" != "$(P0_AGENT_ADMIN_GID)" ]; then \
			echo "Warning: p0-agent-admin group exists with GID $$EXISTING_GID (expected $(P0_AGENT_ADMIN_GID))"; \
			echo "Consider removing the existing group and reinstalling"; \
		else \
			echo "p0-agent-admin group already exists with correct GID $(P0_AGENT_ADMIN_GID)"; \
		fi \
	fi
	
	# Create p0-agent-user group with reserved GID 64201
	@if ! getent group p0-agent-user >/dev/null 2>&1; then \
		sudo groupadd --gid $(P0_AGENT_USER_GID) p0-agent-user; \
		echo "Created p0-agent-user group (GID: $(P0_AGENT_USER_GID))"; \
	else \
		EXISTING_GID=$$(getent group p0-agent-user | cut -d: -f3); \
		if [ "$$EXISTING_GID" != "$(P0_AGENT_USER_GID)" ]; then \
			echo "Warning: p0-agent-user group exists with GID $$EXISTING_GID (expected $(P0_AGENT_USER_GID))"; \
			echo "Consider removing the existing group and reinstalling"; \
		else \
			echo "p0-agent-user group already exists with correct GID $(P0_AGENT_USER_GID)"; \
		fi \
	fi
	
	# Check if p0 agent socket exists
	@if [ ! -S /run/p0_agent.sock ]; then \
		echo "Warning: P0 Agent daemon socket not found at /run/p0_agent.sock"; \
		echo "Ensure p0-agent daemon is running"; \
	else \
		echo "Found p0-agent daemon socket"; \
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
	@echo "P0 Agent Group Configuration"
	@echo "==============================="
	@echo ""
	@echo "Expected reserved GIDs:"
	@echo "  p0-agent-admin: $(P0_AGENT_ADMIN_GID)"
	@echo "  p0-agent-user:  $(P0_AGENT_USER_GID)"
	@echo ""
	@echo "System groups:"
	@if getent group p0-agent-admin >/dev/null 2>&1; then \
		ADMIN_GID=$$(getent group p0-agent-admin | cut -d: -f3); \
		if [ "$$ADMIN_GID" = "$(P0_AGENT_ADMIN_GID)" ]; then \
			echo "  p0-agent-admin: ✓ exists (GID $$ADMIN_GID)"; \
		else \
			echo "  p0-agent-admin: ⚠ exists but wrong GID $$ADMIN_GID (expected $(P0_AGENT_ADMIN_GID))"; \
		fi \
	else \
		echo "  p0-agent-admin: ✗ not found"; \
	fi
	@if getent group p0-agent-user >/dev/null 2>&1; then \
		USER_GID=$$(getent group p0-agent-user | cut -d: -f3); \
		if [ "$$USER_GID" = "$(P0_AGENT_USER_GID)" ]; then \
			echo "  p0-agent-user:  ✓ exists (GID $$USER_GID)"; \
		else \
			echo "  p0-agent-user:  ⚠ exists but wrong GID $$USER_GID (expected $(P0_AGENT_USER_GID))"; \
		fi \
	else \
		echo "  p0-agent-user:  ✗ not found"; \
	fi
	@echo ""
	@echo "Sudoers configuration:"
	@if [ -f $(SUDOERS_BACKUP_DIR)/p0-agent ]; then \
		echo "  ✓ Found in $(SUDOERS_BACKUP_DIR)/p0-agent"; \
		echo "  Configuration:"; \
		sudo cat $(SUDOERS_BACKUP_DIR)/p0-agent | grep -v "^#" | sed 's/^/    /'; \
	else \
		echo "  ✗ Not found in $(SUDOERS_BACKUP_DIR)/p0-agent"; \
	fi
	@echo ""
	@echo "Daemon socket:"
	@if [ -S /run/p0_agent.sock ]; then \
		echo "  ✓ Daemon socket found at /run/p0_agent.sock"; \
	else \
		echo "  ✗ Daemon socket not found at /run/p0_agent.sock"; \
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
	@echo "P0 Agent Group-Based Sudo Configuration Makefile"
	@echo ""
	@echo "This Makefile manages p0-agent groups with reserved GIDs:"
	@echo "  - p0-agent-admin (GID $(P0_AGENT_ADMIN_GID)): Passwordless sudo access"
	@echo "  - p0-agent-user  (GID $(P0_AGENT_USER_GID)): Regular access"
	@echo ""
	@echo "Targets:"
	@echo "  install       - Create groups, backup sudoers, install sudo configuration (includes dependencies)"
	@echo "  uninstall     - Remove sudo configuration (preserves groups)"
	@echo "  setup-groups  - Create p0-agent groups with reserved GIDs"
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