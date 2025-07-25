# Warp Portal PAM Module - Authentication and Session Management
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared -O2 -D_GNU_SOURCE $(shell pkg-config --cflags json-c)
LDFLAGS = -lpam -lpam_misc $(shell pkg-config --libs json-c)
TARGET = pam_sockauth.so
SOURCE = pam_sockauth.c
LOG_FILE = /var/log/pam_sockauth.log

# Detect PAM library directory
PAM_LIB_DIR = $(shell if [ -d /lib/x86_64-linux-gnu/security ]; then \
	echo "/lib/x86_64-linux-gnu/security"; \
	elif [ -d /lib64/security ]; then \
	echo "/lib64/security"; \
	elif [ -d /lib/security ]; then \
	echo "/lib/security"; \
	elif [ -d /usr/lib/x86_64-linux-gnu/security ]; then \
	echo "/usr/lib/x86_64-linux-gnu/security"; \
	elif [ -d /usr/lib64/security ]; then \
	echo "/usr/lib64/security"; \
	elif [ -d /usr/lib/security ]; then \
	echo "/usr/lib/security"; \
	else \
	echo "/lib/security"; \
	fi)

.PHONY: all build clean install uninstall test configure-pam configure-pam-auto backup-pam restore-pam status install-deps test-deps

all: install-deps $(TARGET)

# Build target alias (same as all for consistency)
build: all

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: install-deps $(TARGET) backup-pam
	@echo "Installing PAM module..."
	@test -d $(PAM_LIB_DIR) || (echo "PAM directory $(PAM_LIB_DIR) does not exist" && exit 1)
	sudo cp $(TARGET) $(PAM_LIB_DIR)/
	sudo chmod 644 $(PAM_LIB_DIR)/$(TARGET)
	sudo chown root:root $(PAM_LIB_DIR)/$(TARGET)
	@echo "PAM module installed to $(PAM_LIB_DIR)/$(TARGET)"
	@echo ""
	@echo "Configuring PAM files automatically..."
	$(MAKE) configure-pam-auto
	@echo ""
	@echo "✅ PAM installation and configuration completed!"
	@echo ""
	@echo "⚠️  IMPORTANT: Test authentication in a new session while keeping current session open"
	@echo "   Test commands: 'sudo -l', 'su username', or SSH login"
	@echo "   Check logs: sudo tail -f $(LOG_FILE)"
	@echo ""
	@echo "📋 SSH Configuration Added:"
	@echo "   • Authentication via pam_sockauth.so"
	@echo "   • Automatic home directory creation (pam_mkhomedir.so)"
	@echo "   • Session tracking via pam_sockauth.so (handles socket communication)"

uninstall: restore-pam
	sudo rm -f $(PAM_LIB_DIR)/$(TARGET)
	@echo "PAM module uninstalled from $(PAM_LIB_DIR)/$(TARGET)"
	@echo "PAM configuration has been restored from backups"

restore-pam:
	@echo "Restoring PAM configuration from backups..."
	@if ls /etc/pam.d/sudo.bak.* >/dev/null 2>&1; then \
		LATEST_SUDO_BACKUP=$$(ls -t /etc/pam.d/sudo.bak.* | head -1); \
		echo "Restoring /etc/pam.d/sudo from: $$LATEST_SUDO_BACKUP"; \
		sudo cp "$$LATEST_SUDO_BACKUP" /etc/pam.d/sudo; \
		echo "✅ /etc/pam.d/sudo restored"; \
	else \
		echo "No backup found for /etc/pam.d/sudo. Removing Warp Portal PAM configuration..."; \
		if [ -f /etc/pam.d/sudo ]; then \
			sudo sed -i '/# Warp Portal PAM Configuration/,+2d' /etc/pam.d/sudo; \
			echo "✅ Warp Portal PAM configuration removed from /etc/pam.d/sudo"; \
		fi; \
	fi
	@if ls /etc/pam.d/su.bak.* >/dev/null 2>&1; then \
		LATEST_SU_BACKUP=$$(ls -t /etc/pam.d/su.bak.* | head -1); \
		echo "Restoring /etc/pam.d/su from: $$LATEST_SU_BACKUP"; \
		sudo cp "$$LATEST_SU_BACKUP" /etc/pam.d/su; \
		echo "✅ /etc/pam.d/su restored"; \
	else \
		echo "No backup found for /etc/pam.d/su. Removing Warp Portal PAM configuration..."; \
		if [ -f /etc/pam.d/su ]; then \
			sudo sed -i '/# Warp Portal PAM Configuration/,+2d' /etc/pam.d/su; \
			echo "✅ Warp Portal PAM configuration removed from /etc/pam.d/su"; \
		fi; \
	fi
	@if ls /etc/pam.d/sshd.bak.* >/dev/null 2>&1; then \
		LATEST_SSHD_BACKUP=$$(ls -t /etc/pam.d/sshd.bak.* | head -1); \
		echo "Restoring /etc/pam.d/sshd from: $$LATEST_SSHD_BACKUP"; \
		sudo cp "$$LATEST_SSHD_BACKUP" /etc/pam.d/sshd; \
		echo "✅ /etc/pam.d/sshd restored"; \
	else \
		echo "No backup found for /etc/pam.d/sshd. Removing Warp Portal PAM configuration..."; \
		if [ -f /etc/pam.d/sshd ]; then \
			sudo sed -i '/# Warp Portal PAM Configuration/,+3d' /etc/pam.d/sshd; \
			echo "✅ Warp Portal PAM configuration removed from /etc/pam.d/sshd"; \
		fi; \
	fi

debug: $(SOURCE)
	$(CC) $(CFLAGS) -g -DDEBUG -o $(TARGET) $< $(LDFLAGS)

install-deps:
	@echo "Installing PAM and json-c development dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y libpam0g-dev libjson-c-dev; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y pam-devel json-c-devel; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y pam-devel json-c-devel; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --noconfirm pam json-c; \
	else \
		echo "Package manager not supported. Please install PAM and json-c development packages manually."; \
		exit 1; \
	fi
	@echo "PAM and json-c development dependencies installed successfully"

test-deps:
	@echo "Checking PAM development dependencies..."
	@if [ -f /usr/include/security/pam_modules.h ]; then \
		echo "PAM development headers: OK"; \
	else \
		echo "PAM development headers: MISSING - install libpam0g-dev or pam-devel"; \
	fi

backup-pam:
	@echo "Creating backup of PAM configuration files..."
	@TIMESTAMP=$(shell date +%Y%m%d_%H%M%S); \
	if [ -f /etc/pam.d/sudo ]; then \
		sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak.$$TIMESTAMP; \
		echo "Backup created: /etc/pam.d/sudo.bak.$$TIMESTAMP"; \
	else \
		echo "PAM sudo config not found: /etc/pam.d/sudo"; \
	fi; \
	if [ -f /etc/pam.d/su ]; then \
		sudo cp /etc/pam.d/su /etc/pam.d/su.bak.$$TIMESTAMP; \
		echo "Backup created: /etc/pam.d/su.bak.$$TIMESTAMP"; \
	else \
		echo "PAM su config not found: /etc/pam.d/su"; \
	fi; \
	if [ -f /etc/pam.d/sshd ]; then \
		sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak.$$TIMESTAMP; \
		echo "Backup created: /etc/pam.d/sshd.bak.$$TIMESTAMP"; \
	else \
		echo "PAM sshd config not found: /etc/pam.d/sshd"; \
	fi

configure-pam-auto: backup-pam
	@echo "Configuring PAM files automatically..."
	@echo ""
	@if [ -f /etc/pam.d/sudo ]; then \
		echo "Configuring /etc/pam.d/sudo..."; \
		if ! grep -q "auth.*sufficient.*pam_sockauth.so" /etc/pam.d/sudo; then \
			echo "# Warp Portal PAM Configuration" | sudo tee /tmp/pam_sudo_new > /dev/null; \
			echo "auth    sufficient pam_sockauth.so" | sudo tee -a /tmp/pam_sudo_new > /dev/null; \
			echo "" | sudo tee -a /tmp/pam_sudo_new > /dev/null; \
			sudo cat /etc/pam.d/sudo | sudo tee -a /tmp/pam_sudo_new > /dev/null; \
			sudo mv /tmp/pam_sudo_new /etc/pam.d/sudo; \
			sudo chmod 644 /etc/pam.d/sudo; \
			echo "✅ Added pam_sockauth.so to /etc/pam.d/sudo"; \
		else \
			echo "✅ pam_sockauth.so already configured in /etc/pam.d/sudo"; \
		fi; \
	else \
		echo "❌ /etc/pam.d/sudo not found"; \
	fi
	@if [ -f /etc/pam.d/su ]; then \
		echo "Configuring /etc/pam.d/su..."; \
		if ! grep -q "auth.*sufficient.*pam_sockauth.so" /etc/pam.d/su; then \
			echo "# Warp Portal PAM Configuration" | sudo tee /tmp/pam_su_new > /dev/null; \
			echo "auth    sufficient pam_sockauth.so" | sudo tee -a /tmp/pam_su_new > /dev/null; \
			echo "" | sudo tee -a /tmp/pam_su_new > /dev/null; \
			sudo cat /etc/pam.d/su | sudo tee -a /tmp/pam_su_new > /dev/null; \
			sudo mv /tmp/pam_su_new /etc/pam.d/su; \
			sudo chmod 644 /etc/pam.d/su; \
			echo "✅ Added pam_sockauth.so to /etc/pam.d/su"; \
		else \
			echo "✅ pam_sockauth.so already configured in /etc/pam.d/su"; \
		fi; \
	else \
		echo "❌ /etc/pam.d/su not found"; \
	fi
	@if [ -f /etc/pam.d/sshd ]; then \
		echo "Configuring /etc/pam.d/sshd..."; \
		if ! grep -q "# Warp Portal PAM Configuration" /etc/pam.d/sshd; then \
			echo "# Warp Portal PAM Configuration" | sudo tee /tmp/pam_sshd_new > /dev/null; \
			echo "auth    sufficient pam_sockauth.so" | sudo tee -a /tmp/pam_sshd_new > /dev/null; \
			echo "session required   pam_mkhomedir.so skel=/etc/skel umask=0022" | sudo tee -a /tmp/pam_sshd_new > /dev/null; \
			echo "session optional   pam_sockauth.so" | sudo tee -a /tmp/pam_sshd_new > /dev/null; \
			echo "" | sudo tee -a /tmp/pam_sshd_new > /dev/null; \
			sudo cat /etc/pam.d/sshd | sudo tee -a /tmp/pam_sshd_new > /dev/null; \
			sudo mv /tmp/pam_sshd_new /etc/pam.d/sshd; \
			sudo chmod 644 /etc/pam.d/sshd; \
			echo "✅ Added Warp Portal configuration to /etc/pam.d/sshd"; \
		else \
			echo "✅ Warp Portal configuration already present in /etc/pam.d/sshd"; \
		fi; \
	else \
		echo "❌ /etc/pam.d/sshd not found"; \
	fi
	@echo "PAM configuration completed"

configure-pam: backup-pam
	@echo ""
	@echo "=== PAM Configuration Instructions ==="
	@echo ""
	@echo "IMPORTANT: Always backup your PAM configuration before making changes!"
	@echo "Backups have been created automatically with timestamps."
	@echo ""
	@echo "1. Edit /etc/pam.d/sudo:"
	@echo "   sudo nano /etc/pam.d/sudo"
	@echo ""
	@echo "   Add this line at the TOP of the file:"
	@echo "   auth    sufficient pam_sockauth.so"
	@echo ""
	@echo "   Example configuration:"
	@echo "   auth    sufficient pam_sockauth.so"
	@echo "   auth    required   pam_unix.so"
	@echo "   account required   pam_unix.so"
	@echo ""
	@echo "2. Edit /etc/pam.d/su:"
	@echo "   sudo nano /etc/pam.d/su"
	@echo ""
	@echo "   Add this line at the TOP of the file:"
	@echo "   auth    sufficient pam_sockauth.so"
	@echo ""
	@echo "3. Edit /etc/pam.d/sshd (for SSH session tracking and home directory creation):"
	@echo "   sudo nano /etc/pam.d/sshd"
	@echo ""
	@echo "   Add these lines at the TOP of the file:"
	@echo "   auth    sufficient pam_sockauth.so"
	@echo "   session required   pam_mkhomedir.so skel=/etc/skel umask=0022"
	@echo "   session optional   pam_sockauth.so"
	@echo ""
	@echo "=== CRITICAL SECURITY NOTES ==="
	@echo "• Use 'sufficient' not 'required' to allow fallback authentication"
	@echo "• Place pam_sockauth.so BEFORE other auth modules"
	@echo "• Test thoroughly before closing your current session"
	@echo "• Keep a root session open during testing"
	@echo ""
	@echo "=== Checking for conflicting configurations ==="
	@if [ -f /etc/pam.d/sudo ]; then \
		echo "Current /etc/pam.d/sudo contents:"; \
		sudo cat /etc/pam.d/sudo | head -10; \
		echo ""; \
		if grep -q "auth.*required.*pam_unix.so" /etc/pam.d/sudo && ! grep -q "auth.*sufficient.*pam_sockauth.so" /etc/pam.d/sudo; then \
			echo "WARNING: Found 'required' pam_unix.so without pam_sockauth.so"; \
			echo "Consider changing to 'sufficient' or adding pam_sockauth.so first"; \
		fi; \
	fi
	@if [ -f /etc/pam.d/su ]; then \
		echo "Current /etc/pam.d/su contents:"; \
		sudo cat /etc/pam.d/su | head -10; \
		if grep -q "auth.*required.*pam_unix.so" /etc/pam.d/su && ! grep -q "auth.*sufficient.*pam_sockauth.so" /etc/pam.d/su; then \
			echo "WARNING: Found 'required' pam_unix.so without pam_sockauth.so"; \
			echo "Consider changing to 'sufficient' or adding pam_sockauth.so first"; \
		fi; \
	fi
	@if [ -f /etc/pam.d/sshd ]; then \
		echo "Current /etc/pam.d/sshd contents:"; \
		sudo cat /etc/pam.d/sshd | head -15; \
		echo ""; \
		if ! grep -q "pam_sockauth.so" /etc/pam.d/sshd; then \
			echo "INFO: pam_sockauth.so not found in /etc/pam.d/sshd"; \
			echo "SSH authentication will use default PAM configuration"; \
		fi; \
		if ! grep -q "pam_mkhomedir.so" /etc/pam.d/sshd; then \
			echo "INFO: pam_mkhomedir.so not found in /etc/pam.d/sshd"; \
			echo "Home directories will not be created automatically"; \
		fi; \
	fi

test: $(TARGET)
	@echo "Testing PAM module..."
	@if [ ! -f $(PAM_LIB_DIR)/$(TARGET) ]; then \
		echo "Error: PAM module not installed. Run 'make install' first."; \
		exit 1; \
	fi
	@echo "Module installed: OK"
	@echo "Testing socket connection..."
	@if [ -S /run/warp_portal.sock ]; then \
		echo "Warp Portal daemon socket: OK"; \
	else \
		echo "WARNING: Warp Portal daemon socket not found"; \
		echo "Make sure the daemon is running"; \
	fi
	@echo "Checking log file permissions..."
	@sudo touch $(LOG_FILE)
	@sudo chmod 666 $(LOG_FILE)
	@echo "Log file: OK"
	@echo ""
	@echo "Manual test: Try 'sudo -l' or 'su' to test authentication"
	@echo "Check logs: tail -f $(LOG_FILE)"

status:
	@echo "=== PAM Module Status ==="
	@echo "Module path: $(PAM_LIB_DIR)/$(TARGET)"
	@if [ -f $(PAM_LIB_DIR)/$(TARGET) ]; then \
		echo "Module status: INSTALLED"; \
		ls -la $(PAM_LIB_DIR)/$(TARGET); \
	else \
		echo "Module status: NOT INSTALLED"; \
	fi
	@echo ""
	@echo "=== PAM Configuration Status ==="
	@if [ -f /etc/pam.d/sudo ]; then \
		if grep -q "pam_sockauth.so" /etc/pam.d/sudo; then \
			echo "sudo PAM config: CONFIGURED"; \
		else \
			echo "sudo PAM config: NOT CONFIGURED"; \
		fi; \
	else \
		echo "sudo PAM config: FILE NOT FOUND"; \
	fi
	@if [ -f /etc/pam.d/su ]; then \
		if grep -q "pam_sockauth.so" /etc/pam.d/su; then \
			echo "su PAM config: CONFIGURED"; \
		else \
			echo "su PAM config: NOT CONFIGURED"; \
		fi; \
	else \
		echo "su PAM config: FILE NOT FOUND"; \
	fi
	@if [ -f /etc/pam.d/sshd ]; then \
		AUTH_CONFIGURED=$$(grep -c "auth.*sufficient.*pam_sockauth.so" /etc/pam.d/sshd 2>/dev/null || echo 0); \
		SESSION_CONFIGURED=$$(grep -c "session.*pam_sockauth.so" /etc/pam.d/sshd 2>/dev/null || echo 0); \
		HOMEDIR_CONFIGURED=$$(grep -c "pam_mkhomedir.so" /etc/pam.d/sshd 2>/dev/null || echo 0); \
		if [ "$$AUTH_CONFIGURED" -gt 0 ] && [ "$$SESSION_CONFIGURED" -gt 0 ] && [ "$$HOMEDIR_CONFIGURED" -gt 0 ]; then \
			echo "sshd PAM config: FULLY CONFIGURED (auth + session + homedir)"; \
		elif [ "$$AUTH_CONFIGURED" -gt 0 ] || [ "$$SESSION_CONFIGURED" -gt 0 ] || [ "$$HOMEDIR_CONFIGURED" -gt 0 ]; then \
			echo "sshd PAM config: PARTIALLY CONFIGURED"; \
		else \
			echo "sshd PAM config: NOT CONFIGURED"; \
		fi; \
	else \
		echo "sshd PAM config: FILE NOT FOUND"; \
	fi
	@echo ""
	@echo "=== Log File Status ==="
	@if [ -f $(LOG_FILE) ]; then \
		echo "Log file: EXISTS"; \
		ls -la $(LOG_FILE); \
		echo "Recent log entries:"; \
		sudo tail -5 $(LOG_FILE) 2>/dev/null || echo "No recent entries"; \
	else \
		echo "Log file: NOT FOUND"; \
	fi

logs:
	@if [ -f $(LOG_FILE) ]; then \
		echo "Tailing PAM authentication log..."; \
		sudo tail -f $(LOG_FILE); \
	else \
		echo "Log file not found: $(LOG_FILE)"; \
		echo "Run 'make test' to create it"; \
	fi

help:
	@echo "Available targets:"
	@echo "  all               - Build the PAM module"
	@echo "  install           - Install module and configure PAM automatically (includes dependencies)"
	@echo "  uninstall         - Remove module and restore PAM configuration"
	@echo "  configure-pam-auto- Configure PAM files automatically (with backups)"
	@echo "  configure-pam     - Show manual PAM configuration instructions"
	@echo "  backup-pam        - Backup current PAM configuration"
	@echo "  restore-pam       - Restore PAM configuration from backups"
	@echo "  test              - Test module installation"
	@echo "  status            - Show installation and configuration status"
	@echo "  logs              - Show authentication logs"
	@echo "  install-deps      - Install PAM development dependencies"
	@echo "  test-deps         - Check if dependencies are installed"
	@echo "  clean             - Remove built files"
	@echo "  debug             - Build with debug symbols"
	@echo "  help              - Show this help message"
	@echo ""
	@echo "Installation workflow:"
	@echo "  1. make install          # Installs binary and configures PAM automatically"
	@echo "  2. make test             # Test the module"
	@echo ""
	@echo "Manual configuration (if needed):"
	@echo "  make configure-pam       # Show manual configuration instructions"