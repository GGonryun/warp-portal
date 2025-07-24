package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"warp_portal_daemon/config"
	"warp_portal_daemon/logging"
	"warp_portal_daemon/providers"
	"warp_portal_daemon/socket"

	"gopkg.in/yaml.v3"
)

// Type aliases for provider types
type DataProvider = providers.DataProvider

var (
	dataProvider DataProvider
	providerMu   sync.RWMutex
)

// Main daemon logger
var logger = logging.NewLogger("daemon")

func initializeLogging() error {
	// Read config file to get log level if it exists
	if data, err := os.ReadFile(config.ConfigPath); err == nil {
		var config struct {
			LogLevel string `json:"log_level" yaml:"log_level"`
		}

		// Try to parse as YAML first, then JSON
		if yaml.Unmarshal(data, &config) == nil && config.LogLevel != "" {
			if !logging.SetGlobalLogLevelFromString(config.LogLevel) {
				logger.Warn("Invalid log level '%s' in config, using default 'info'", config.LogLevel)
			} else {
				logger.Info("Log level set to: %s", config.LogLevel)
			}
		}
	}
	return nil
}

func initializeProvider() error {
	// Initialize provider based on config
	provider, err := providers.InitializeProvider(config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to initialize provider: %v", err)
	}

	// Set the global provider
	providerMu.Lock()
	dataProvider = provider
	providerMu.Unlock()

	return nil
}

func initializeSocket() (net.Listener, error) {
	// Remove existing socket if it exists
	if err := os.Remove(config.SocketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket: %v", err)
	}

	// Create Unix domain socket
	listener, err := net.Listen("unix", config.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	// Set socket permissions
	if err := os.Chmod(config.SocketPath, 0666); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set socket permissions: %v", err)
	}

	logger.Trace("Warp portal daemon listening on %s", config.SocketPath)
	return listener, nil
}

func main() {
	logging.SetupLogging(config.LogPath)

	// Initialize logging configuration
	if err := initializeLogging(); err != nil {
		logger.Warn("Failed to initialize logging configuration: %v", err)
	}

	// Initialize data provider
	if err := initializeProvider(); err != nil {
		logger.Fatal("Failed to initialize data provider: %v", err)
	}

	// Initialize socket
	listener, err := initializeSocket()
	if err != nil {
		logger.Fatal("Failed to initialize socket: %v", err)
	}
	defer listener.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, cleaning up...")
		listener.Close()
		os.Remove(config.SocketPath)
		os.Exit(0)
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		// Create socket handler with current provider
		providerMu.RLock()
		provider := dataProvider
		providerMu.RUnlock()

		handler := socket.NewHandler(provider)
		go handler.HandleConnection(conn)
	}
}
