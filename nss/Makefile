CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared -O2 -D_GNU_SOURCE
LDFLAGS = -ljson-c -lpthread
TARGET = libnss_socket.so.2
SOURCE = nss_socket.c
INSTALL_DIR = $(shell gcc -print-multiarch 2>/dev/null | sed 's/^/\/lib\//' || \
              (test -d /usr/lib/x86_64-linux-gnu && echo "/usr/lib/x86_64-linux-gnu") || \
              (test -d /usr/lib && echo "/usr/lib") || \
              echo "/lib")

.PHONY: all clean install uninstall install-deps restart

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@test -d $(INSTALL_DIR) || (echo "Installation directory $(INSTALL_DIR) does not exist" && exit 1)
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo ldconfig
	@echo "NSS plugin installed. Add 'socket' to your /etc/nsswitch.conf"
	@echo "Example: passwd: files socket"
	@echo "Example: group: files socket"

uninstall:
	sudo rm -f $(INSTALL_DIR)/$(TARGET)
	sudo ldconfig
	@echo "NSS plugin uninstalled. Remove 'socket' from your /etc/nsswitch.conf"

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