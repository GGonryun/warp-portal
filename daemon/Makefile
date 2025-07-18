BINARY_NAME = nss-daemon
PID_FILE = /run/nss-daemon.pid
LOG_FILE = /var/log/nss-daemon.log
SOCKET_PATH = /run/nss-forward.sock

.PHONY: all build clean start stop restart status install uninstall install-deps install-service enable-service disable-service

all: build

build:
	go build -o $(BINARY_NAME) main.go

clean:
	rm -f $(BINARY_NAME)

start: build
	@echo "Starting NSS daemon..."
	@if [ -f $(PID_FILE) ]; then \
		echo "Daemon already running (PID: $$(cat $(PID_FILE)))"; \
		exit 1; \
	fi
	@sudo ./$(BINARY_NAME) >> $(LOG_FILE) 2>&1 & echo $$! | sudo tee $(PID_FILE) > /dev/null
	@sleep 1
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "Daemon started successfully (PID: $$(cat $(PID_FILE)))"; \
	else \
		echo "Failed to start daemon"; \
		exit 1; \
	fi

stop:
	@echo "Stopping NSS daemon..."
	@if [ -f $(PID_FILE) ]; then \
		sudo kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		sudo rm -f $(PID_FILE); \
		sudo rm -f $(SOCKET_PATH); \
		echo "Daemon stopped"; \
	else \
		echo "Daemon not running"; \
	fi

restart: stop start

status:
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "Daemon is running (PID: $$(cat $(PID_FILE)))"; \
	else \
		echo "Daemon is not running"; \
	fi

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

install: build
	sudo mkdir -p $(BINDIR)
	sudo cp $(BINARY_NAME) $(BINDIR)/
	sudo chmod +x $(BINDIR)/$(BINARY_NAME)
	@echo "Daemon installed to $(BINDIR)/$(BINARY_NAME)"

install-service: install
	@echo "Installing systemd service..."
	sudo cp nss-daemon.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Service installed. Use 'make enable-service' to enable auto-start"

enable-service:
	@echo "Enabling and starting NSS daemon service..."
	sudo systemctl enable nss-daemon.service
	sudo systemctl start nss-daemon.service
	sudo systemctl status nss-daemon.service --no-pager
	@echo "Service enabled for auto-start on boot"

disable-service:
	@echo "Disabling NSS daemon service..."
	sudo systemctl stop nss-daemon.service || true
	sudo systemctl disable nss-daemon.service || true
	@echo "Service disabled"

uninstall: disable-service stop
	sudo rm -f $(BINDIR)/$(BINARY_NAME)
	sudo rm -f /etc/systemd/system/nss-daemon.service
	sudo systemctl daemon-reload || true
	sudo rm -f $(PID_FILE)
	sudo rm -f $(SOCKET_PATH)
	@echo "Daemon uninstalled"

logs:
	@if [ -f $(LOG_FILE) ]; then \
		tail -f $(LOG_FILE); \
	else \
		echo "Log file not found: $(LOG_FILE)"; \
	fi

install-deps:
	@echo "Installing dependencies..."
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Installing Go..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y golang-go; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y golang; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y golang; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm go; \
		else \
			echo "Package manager not supported. Please install Go manually from https://golang.org/dl/"; \
			exit 1; \
		fi; \
	else \
		echo "Go: Already installed"; \
	fi
	@echo "All dependencies installed successfully"

test-deps:
	@echo "Checking Go installation..."
	@go version || (echo "Go is not installed" && exit 1)
	@echo "Go is installed"

test: build
	@echo "Testing daemon (will run for 10 seconds)..."
	@sudo ./$(BINARY_NAME) & TEST_PID=$$!; \
	sleep 2; \
	echo "Testing user lookup..."; \
	getent passwd $(USER) || echo "NSS plugin not configured"; \
	echo "Testing group lookup..."; \
	getent group $(shell id -gn) || echo "NSS plugin not configured"; \
	sleep 8; \
	sudo kill $$TEST_PID 2>/dev/null || true; \
	sudo rm -f $(SOCKET_PATH); \
	echo "Test completed"

help:
	@echo "Available targets:"
	@echo "  build     - Build the daemon binary"
	@echo "  start     - Start the daemon in background"
	@echo "  stop      - Stop the daemon"
	@echo "  restart   - Restart the daemon"
	@echo "  status    - Check daemon status"
	@echo "  install         - Install daemon to /usr/local/bin"
	@echo "  install-service - Install systemd service"
	@echo "  enable-service  - Enable auto-start on boot"
	@echo "  disable-service - Disable auto-start"
	@echo "  uninstall       - Remove daemon and cleanup"
	@echo "  logs            - Show daemon logs (tail -f)"
	@echo "  test            - Run a quick test"
	@echo "  test-deps       - Check dependencies"
	@echo "  clean           - Remove binary"
	@echo "  help            - Show this help"