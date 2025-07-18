BINARY_NAME = nss-daemon
PID_FILE = /var/run/nss-daemon.pid
LOG_FILE = /var/log/nss-daemon.log
SOCKET_PATH = /run/nss-forward.sock

.PHONY: all build clean start stop restart status install uninstall

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

install: build
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Daemon installed to /usr/local/bin/$(BINARY_NAME)"

uninstall: stop
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	sudo rm -f $(PID_FILE)
	sudo rm -f $(SOCKET_PATH)
	@echo "Daemon uninstalled"

logs:
	@if [ -f $(LOG_FILE) ]; then \
		tail -f $(LOG_FILE); \
	else \
		echo "Log file not found: $(LOG_FILE)"; \
	fi

test-deps:
	@echo "Checking Go installation..."
	@go version || (echo "Go is not installed" && exit 1)
	@echo "Go is installed"

test: build
	@echo "Testing daemon (will run for 10 seconds)..."
	@sudo ./$(BINARY_NAME) & TEST_PID=$$!; \
	sleep 2; \
	echo "Testing user lookup..."; \
	getent passwd miguel || echo "NSS plugin not configured"; \
	echo "Testing group lookup..."; \
	getent group users || echo "NSS plugin not configured"; \
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
	@echo "  install   - Install daemon to /usr/local/bin"
	@echo "  uninstall - Remove daemon and cleanup"
	@echo "  logs      - Show daemon logs (tail -f)"
	@echo "  test      - Run a quick test"
	@echo "  test-deps - Check dependencies"
	@echo "  clean     - Remove binary"
	@echo "  help      - Show this help"