CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared -O2 -D_GNU_SOURCE
LDFLAGS = -ljson-c -lpthread
TARGET = libnss_socket.so.2
SOURCE = nss_socket.c
INSTALL_DIR = /lib/x86_64-linux-gnu

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
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

test-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists json-c && echo "json-c: OK" || echo "json-c: MISSING - install libjson-c-dev"
	@echo "pthread: OK (part of glibc)"