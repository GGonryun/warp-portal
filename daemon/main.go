package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"p0_agent_daemon/config"
	"p0_agent_daemon/logging"
	"p0_agent_daemon/providers"
	"p0_agent_daemon/socket"

	"gopkg.in/yaml.v3"
)

type DataProvider = providers.DataProvider

var (
	dataProvider DataProvider
	cacheManager *providers.CacheManager
	providerMu   sync.RWMutex
)

var logger = logging.NewLogger("daemon")

func initializeLogging() error {
	if data, err := os.ReadFile(config.ConfigPath); err == nil {
		var config struct {
			LogLevel string `json:"log_level" yaml:"log_level"`
		}

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
	provider, err := providers.InitializeProvider(config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to initialize provider: %v", err)
	}

	var providerConfig providers.Config
	if data, err := os.ReadFile(config.ConfigPath); err == nil {
		if yaml.Unmarshal(data, &providerConfig) == nil {
			cm, err := providers.NewCacheManager(&providerConfig, provider)
			if err != nil {
				logger.Warn("Failed to initialize cache manager: %v", err)
			} else {
				if err := cm.Start(); err != nil {
					logger.Warn("Failed to start cache manager: %v", err)
				} else {
					cacheManager = cm
					logger.Info("Cache manager initialized and started")
				}
			}
		}
	}

	providerMu.Lock()
	dataProvider = provider
	providerMu.Unlock()

	return nil
}

func initializeSocket() (net.Listener, error) {
	if err := os.Remove(config.SocketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket: %v", err)
	}

	listener, err := net.Listen("unix", config.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	if err := os.Chmod(config.SocketPath, 0666); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set socket permissions: %v", err)
	}

	logger.Trace("P0 agent daemon listening on %s", config.SocketPath)
	return listener, nil
}

func main() {
	logging.SetupLogging(config.LogPath)

	if err := initializeLogging(); err != nil {
		logger.Warn("Failed to initialize logging configuration: %v", err)
	}

	if err := initializeProvider(); err != nil {
		logger.Fatal("Failed to initialize data provider: %v", err)
	}

	listener, err := initializeSocket()
	if err != nil {
		logger.Fatal("Failed to initialize socket: %v", err)
	}
	defer listener.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, cleaning up...")

		if cacheManager != nil {
			cacheManager.Stop()
		}

		listener.Close()
		os.Remove(config.SocketPath)
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		providerMu.RLock()
		provider := dataProvider
		providerMu.RUnlock()

		handler := socket.NewHandler(provider, cacheManager)
		go handler.HandleConnection(conn)
	}
}
