CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared -O2 -D_GNU_SOURCE
LDFLAGS = -ljson-c -lpthread
TARGET = libnss_socket.so.2
SOURCE = nss_socket.c
INSTALL_DIR = $(shell gcc -print-multiarch 2>/dev/null | sed 's/^/\/lib\//' || \
              (test -d /usr/lib/x86_64-linux-gnu && echo "/usr/lib/x86_64-linux-gnu") || \
              (test -d /usr/lib && echo "/usr/lib") || \
              echo "/lib")

.PHONY: all clean install uninstall install-deps restart logs backup-nsswitch restore-nsswitch configure-nsswitch

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

backup-nsswitch:
	@echo "Creating backup of /etc/nsswitch.conf..."
	@if [ -f /etc/nsswitch.conf ]; then \
		sudo cp /etc/nsswitch.conf /etc/nsswitch.conf.bak.$(shell date +%Y%m%d_%H%M%S); \
		echo "Backup created: /etc/nsswitch.conf.bak.$(shell date +%Y%m%d_%H%M%S)"; \
	else \
		echo "No /etc/nsswitch.conf found"; \
	fi

configure-nsswitch:
	@echo "Configuring /etc/nsswitch.conf..."
	@if ! grep -q "socket" /etc/nsswitch.conf; then \
		echo "Adding socket to NSS configuration..."; \
		sudo sed -i.bak 's/^passwd:.*files.*/& socket/' /etc/nsswitch.conf; \
		sudo sed -i.bak 's/^group:.*files.*/& socket/' /etc/nsswitch.conf; \
		echo "NSS configuration updated"; \
	else \
		echo "Socket already configured in /etc/nsswitch.conf"; \
	fi

restore-nsswitch:
	@echo "Restoring /etc/nsswitch.conf..."
	@if ls /etc/nsswitch.conf.bak.* >/dev/null 2>&1; then \
		LATEST_BACKUP=$$(ls -t /etc/nsswitch.conf.bak.* | head -1); \
		sudo cp "$$LATEST_BACKUP" /etc/nsswitch.conf; \
		echo "Restored from: $$LATEST_BACKUP"; \
	else \
		echo "Removing socket from NSS configuration..."; \
		sudo sed -i 's/ socket//g' /etc/nsswitch.conf; \
		echo "Socket removed from NSS configuration"; \
	fi

install: install-deps $(TARGET) backup-nsswitch
	@echo "Installing NSS module..."
	@test -d $(INSTALL_DIR) || (echo "Installation directory $(INSTALL_DIR) does not exist" && exit 1)
	@if [ -f $(INSTALL_DIR)/$(TARGET) ]; then sudo rm -f $(INSTALL_DIR)/$(TARGET); fi
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo ldconfig
	@echo "NSS plugin installed to $(INSTALL_DIR)/$(TARGET)"
	$(MAKE) configure-nsswitch
	@echo "NSS module installation complete"

uninstall: restore-nsswitch
	@echo "Uninstalling NSS module..."
	sudo rm -f $(INSTALL_DIR)/$(TARGET)
	sudo ldconfig
	@echo "NSS plugin uninstalled and configuration restored"

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
	@echo "pthread: OK (part of glibc)"

restart:
	@echo "Restarting NSS services..."
	@if command -v systemctl >/dev/null 2>&1; then \
		sudo systemctl restart nscd || echo "nscd not running"; \
		sudo systemctl restart sssd || echo "sssd not running"; \
	else \
		echo "System does not use systemctl. Please restart NSS services manually."; \
	fi

logs:
	@if [ -f /var/log/nss_socket.log ]; then \
		tail -f /var/log/nss_socket.log; \
	else \
		echo "Log file not found: /var/log/nss_socket.log"; \
	fi