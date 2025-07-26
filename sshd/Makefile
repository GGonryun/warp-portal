CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -ljson-c
TARGET = authorized_keys_socket
SOURCE = authorized_keys_socket.c
INSTALL_DIR = /usr/local/bin
CONFIG_FILE = /etc/ssh/sshd_config

.PHONY: all build clean install uninstall install-deps test-deps configure-ssh restart-ssh backup-config restore-config

all: $(TARGET)

# Build target alias (same as all for consistency)
build: all

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET) backup-config
	@echo "Installing SSH authorized keys module..."
	@echo ""
	@test -d $(INSTALL_DIR) || (echo "Installation directory $(INSTALL_DIR) does not exist" && exit 1)
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo chmod 755 $(INSTALL_DIR)/$(TARGET)
	sudo chown root:root $(INSTALL_DIR)/$(TARGET)
	@echo "SSH authorized keys module installed to $(INSTALL_DIR)/$(TARGET)"
	@echo ""
	@echo "Configuring SSH daemon automatically..."
	$(MAKE) configure-ssh
	@echo ""
	@echo "Validating SSH configuration..."
	@if sudo sshd -t; then \
		echo "✅ SSH configuration is valid"; \
		echo ""; \
		echo "✅ SSH installation and configuration completed!"; \
		echo ""; \
		echo "⚠️  IMPORTANT: SSH service must be restarted to apply changes"; \
		echo "   Run: sudo systemctl restart sshd"; \
		echo "   Or:  make restart-ssh"; \
		echo ""; \
		echo "   Make sure you have alternative access if connecting remotely"; \
	else \
		echo "❌ SSH configuration validation failed!"; \
		echo "Please check the configuration manually before restarting SSH"; \
		exit 1; \
	fi

uninstall: restore-config
	sudo rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "SSH authorized keys module uninstalled"
	@echo "SSH configuration has been restored from backup"
	@echo "Restarting SSH service to apply restored configuration..."
	$(MAKE) restart-ssh
	@echo "✅ SSH module uninstallation and configuration restoration completed!"

restore-config:
	@echo "Restoring SSH configuration from backup..."
	@if ls $(CONFIG_FILE).bak.* >/dev/null 2>&1; then \
		LATEST_BACKUP=$$(ls -t $(CONFIG_FILE).bak.* | head -1); \
		echo "Restoring from: $$LATEST_BACKUP"; \
		sudo cp "$$LATEST_BACKUP" $(CONFIG_FILE); \
		echo "SSH configuration restored"; \
		echo "Run 'make restart-ssh' to apply restored configuration"; \
	else \
		echo "No backup found. Removing Warp Portal SSH configuration..."; \
		sudo sed -i '/# Warp Portal SSH Configuration/,+5d' $(CONFIG_FILE); \
		echo "Warp Portal SSH configuration removed"; \
		echo "Run 'make restart-ssh' to apply changes"; \
	fi

debug: $(SOURCE)
	$(CC) $(CFLAGS) -g -DDEBUG -o $(TARGET) $< $(LDFLAGS)

install-deps:
	@echo "Installing dependencies..."
	@if ! pkg-config --exists json-c; then \
		echo "Installing json-c development package..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y libjson-c-dev; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y json-c-devel; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y json-c-devel; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm json-c; \
		else \
			echo "Package manager not supported. Please install json-c development package manually."; \
			exit 1; \
		fi; \
	else \
		echo "json-c: Already installed"; \
	fi
	@echo "All dependencies installed successfully"

test-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists json-c && echo "json-c: OK" || echo "json-c: MISSING - install libjson-c-dev"

backup-config:
	@echo "Creating backup of SSH configuration..."
	@if [ -f $(CONFIG_FILE) ]; then \
		sudo cp $(CONFIG_FILE) $(CONFIG_FILE).bak.$(shell date +%Y%m%d_%H%M%S); \
		echo "Backup created: $(CONFIG_FILE).bak.$(shell date +%Y%m%d_%H%M%S)"; \
	else \
		echo "SSH config file not found: $(CONFIG_FILE)"; \
	fi

configure-ssh: backup-config
	@echo "Configuring SSH daemon automatically..."
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "Error: SSH config file not found: $(CONFIG_FILE)"; \
		exit 1; \
	fi
	@echo "Applying SSH configuration changes..."
	
	# Comment out conflicting PasswordAuthentication lines
	@if grep -q "^PasswordAuthentication" $(CONFIG_FILE); then \
		echo "Disabling existing PasswordAuthentication settings..."; \
		sudo sed -i.bak 's/^PasswordAuthentication.*/#&/' $(CONFIG_FILE); \
	fi
	
	# Comment out conflicting ChallengeResponseAuthentication lines
	@if grep -q "^ChallengeResponseAuthentication" $(CONFIG_FILE); then \
		echo "Disabling existing ChallengeResponseAuthentication settings..."; \
		sudo sed -i.bak 's/^ChallengeResponseAuthentication.*/#&/' $(CONFIG_FILE); \
	fi
	
	# Comment out existing AuthorizedKeysCommand lines
	@if grep -q "^AuthorizedKeysCommand" $(CONFIG_FILE); then \
		echo "Disabling existing AuthorizedKeysCommand settings..."; \
		sudo sed -i.bak 's/^AuthorizedKeysCommand.*/#&/' $(CONFIG_FILE); \
	fi
	
	# Comment out existing AuthorizedKeysCommandUser lines
	@if grep -q "^AuthorizedKeysCommandUser" $(CONFIG_FILE); then \
		echo "Disabling existing AuthorizedKeysCommandUser settings..."; \
		sudo sed -i.bak 's/^AuthorizedKeysCommandUser.*/#&/' $(CONFIG_FILE); \
	fi
	
	# Add Warp Portal SSH configuration block
	@echo "" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "# Warp Portal SSH Configuration" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "PasswordAuthentication no" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "AuthenticationMethods publickey" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "ChallengeResponseAuthentication no" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "AuthorizedKeysCommand $(INSTALL_DIR)/$(TARGET) %t %k %u" | sudo tee -a $(CONFIG_FILE) >/dev/null
	@echo "AuthorizedKeysCommandUser root" | sudo tee -a $(CONFIG_FILE) >/dev/null
	
	@echo "SSH configuration updated successfully"
	@echo "Configuration backup saved as: $(CONFIG_FILE).bak.*"
	@echo "Run 'make restart-ssh' to apply changes"

restart-ssh:
	@echo "Restarting SSH service..."
	@if command -v systemctl >/dev/null 2>&1; then \
		sudo systemctl restart sshd || sudo systemctl restart ssh; \
		echo "SSH service restarted"; \
		sudo systemctl status sshd || sudo systemctl status ssh; \
	elif command -v service >/dev/null 2>&1; then \
		sudo service ssh restart || sudo service sshd restart; \
		echo "SSH service restarted"; \
	else \
		echo "Cannot restart SSH service automatically. Please restart manually."; \
		echo "Common commands: 'sudo systemctl restart sshd' or 'sudo service ssh restart'"; \
	fi

test:
	@echo "Testing SSH authorized keys module..."
	@if [ ! -f $(INSTALL_DIR)/$(TARGET) ]; then \
		echo "Error: Module not installed. Run 'make install' first."; \
		exit 1; \
	fi
	@echo "Testing with user 'miguel'..."
	@$(INSTALL_DIR)/$(TARGET) "ssh-rsa" "dummy_fingerprint" "miguel" || echo "Test completed (check daemon logs for details)"

status:
	@echo "=== SSH Authorized Keys Module Status ==="
	@echo "Binary location: $(INSTALL_DIR)/$(TARGET)"
	@if [ -f $(INSTALL_DIR)/$(TARGET) ]; then \
		echo "Status: INSTALLED"; \
		ls -la $(INSTALL_DIR)/$(TARGET); \
	else \
		echo "Status: NOT INSTALLED"; \
	fi
	@echo ""
	@echo "=== SSH Configuration Status ==="
	@if [ -f $(CONFIG_FILE) ]; then \
		echo "Config file: $(CONFIG_FILE)"; \
		if grep -q "AuthorizedKeysCommand.*$(TARGET)" $(CONFIG_FILE); then \
			echo "AuthorizedKeysCommand: CONFIGURED"; \
		else \
			echo "AuthorizedKeysCommand: NOT CONFIGURED"; \
		fi; \
	else \
		echo "SSH config file not found"; \
	fi

help:
	@echo "Available targets:"
	@echo "  all              - Build the module"
	@echo "  install          - Install the module and configure SSH automatically"
	@echo "  uninstall        - Remove the module and restore SSH configuration"
	@echo "  configure-ssh    - Configure SSH daemon for Warp Portal (automatic)"
	@echo "  restore-config   - Restore SSH configuration from backup"
	@echo "  restart-ssh      - Restart SSH service"
	@echo "  backup-config    - Backup SSH configuration"
	@echo "  test             - Test the module"
	@echo "  status           - Show installation and configuration status"
	@echo "  install-deps     - Install required dependencies"
	@echo "  test-deps        - Check if dependencies are installed"
	@echo "  clean            - Remove built files"
	@echo "  debug            - Build with debug symbols"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Installation workflow:"
	@echo "  1. make install          # Installs binary, configures SSH, and restarts SSH service"
	@echo "  2. make test             # Test the module"
	@echo ""
	@echo "Manual restart (if needed):"
	@echo "  make restart-ssh         # Manually restart SSH service"