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

.PHONY: all build clean install uninstall test configure-pam backup-pam status install-deps test-deps

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
	@echo "IMPORTANT: PAM configuration requires manual setup for security reasons"
	@echo "Run 'make configure-pam' to see detailed configuration instructions"

uninstall:
	sudo rm -f $(PAM_LIB_DIR)/$(TARGET)
	@echo "PAM module uninstalled from $(PAM_LIB_DIR)/$(TARGET)"
	@echo "Remember to remove module references from PAM configuration files"

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
	@if [ -f /etc/pam.d/sudo ]; then \
		sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak.$(shell date +%Y%m%d_%H%M%S); \
		echo "Backup created: /etc/pam.d/sudo.bak.$(shell date +%Y%m%d_%H%M%S)"; \
	else \
		echo "PAM sudo config not found: /etc/pam.d/sudo"; \
	fi
	@if [ -f /etc/pam.d/su ]; then \
		sudo cp /etc/pam.d/su /etc/pam.d/su.bak.$(shell date +%Y%m%d_%H%M%S); \
		echo "Backup created: /etc/pam.d/su.bak.$(shell date +%Y%m%d_%H%M%S)"; \
	else \
		echo "PAM su config not found: /etc/pam.d/su"; \
	fi

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
	@echo "  all           - Build the PAM module"
	@echo "  install       - Install module to PAM directory (includes dependencies)"
	@echo "  uninstall     - Remove module from system"
	@echo "  configure-pam - Show PAM configuration instructions"
	@echo "  backup-pam    - Backup current PAM configuration"
	@echo "  test          - Test module installation"
	@echo "  status        - Show installation and configuration status"
	@echo "  logs          - Show authentication logs"
	@echo "  install-deps  - Install PAM development dependencies"
	@echo "  test-deps     - Check if dependencies are installed"
	@echo "  clean         - Remove built files"
	@echo "  debug         - Build with debug symbols"
	@echo "  help          - Show this help message"