CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -ljson-c
TARGET = authorized_keys_socket
SOURCE = authorized_keys_socket.c
INSTALL_DIR = /usr/local/bin
CONFIG_FILE = /etc/ssh/sshd_config

.PHONY: all clean install uninstall install-deps test-deps configure-ssh restart-ssh backup-config restore-config

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Installing SSH authorized keys module..."
	@test -d $(INSTALL_DIR) || (echo "Installation directory $(INSTALL_DIR) does not exist" && exit 1)
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo chmod 755 $(INSTALL_DIR)/$(TARGET)
	@echo "SSH authorized keys module installed to $(INSTALL_DIR)/$(TARGET)"
	@echo ""
	@echo "Next steps:"
	@echo "1. Run 'make configure-ssh' to configure SSH daemon"
	@echo "2. Run 'make restart-ssh' to restart SSH service"

uninstall:
	sudo rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "SSH authorized keys module uninstalled"
	@echo "Remember to remove configuration from $(CONFIG_FILE)"

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
	@echo "Configuring SSH daemon..."
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "Error: SSH config file not found: $(CONFIG_FILE)"; \
		exit 1; \
	fi
	@echo ""
	@echo "=== SSH Configuration Required ==="
	@echo "Add these lines to $(CONFIG_FILE):"
	@echo ""
	@echo "PasswordAuthentication no"
	@echo "AuthenticationMethods publickey"
	@echo "ChallengeResponseAuthentication no"
	@echo "AuthorizedKeysCommand $(INSTALL_DIR)/$(TARGET) %t %k %u"
	@echo "AuthorizedKeysCommandUser root"
	@echo ""
	@echo "=== Checking for conflicting configurations ==="
	@if grep -q "^PasswordAuthentication yes" $(CONFIG_FILE); then \
		echo "WARNING: Found 'PasswordAuthentication yes' - should be commented out or changed to 'no'"; \
	fi
	@if grep -q "^ChallengeResponseAuthentication yes" $(CONFIG_FILE); then \
		echo "WARNING: Found 'ChallengeResponseAuthentication yes' - should be commented out or changed to 'no'"; \
	fi
	@if grep -q "^AuthorizedKeysCommand" $(CONFIG_FILE); then \
		echo "WARNING: Found existing 'AuthorizedKeysCommand' - may conflict with new configuration"; \
	fi
	@if grep -q "^AuthorizedKeysCommandUser" $(CONFIG_FILE); then \
		echo "WARNING: Found existing 'AuthorizedKeysCommandUser' - may conflict with new configuration"; \
	fi
	@echo ""
	@echo "=== Manual Configuration Required ==="
	@echo "Please manually edit $(CONFIG_FILE) with the above configuration."
	@echo "After editing, run 'make restart-ssh' to apply changes."

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
	@echo "  install          - Install the module to $(INSTALL_DIR)"
	@echo "  uninstall        - Remove the module"
	@echo "  configure-ssh    - Show SSH configuration instructions"
	@echo "  restart-ssh      - Restart SSH service"
	@echo "  backup-config    - Backup SSH configuration"
	@echo "  test             - Test the module"
	@echo "  status           - Show installation and configuration status"
	@echo "  install-deps     - Install required dependencies"
	@echo "  test-deps        - Check if dependencies are installed"
	@echo "  clean            - Remove built files"
	@echo "  debug            - Build with debug symbols"
	@echo "  help             - Show this help message"