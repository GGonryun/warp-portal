package providers

import (
	"fmt"
	"os"
	
	"warp_portal_daemon/logging"
	"gopkg.in/yaml.v3"
)

// Factory logger
var factoryLog = logging.NewLogger("factory")

// InitializeProvider reads the configuration file and returns the appropriate provider
func InitializeProvider(configPath string) (DataProvider, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Use file provider with defaults if no config file
		factoryLog.Warn("Config file not found at %s, using file provider with defaults", configPath)
		return NewFileProvider(configPath), nil
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %v", err)
	}

	// Determine provider type (default to file)
	providerType := config.Provider.Type
	if providerType == "" {
		providerType = "file"
	}

	// Initialize the appropriate provider
	switch providerType {
	case "file":
		provider := NewFileProvider(configPath)
		if err := provider.Reload(); err != nil {
			return nil, fmt.Errorf("failed to initialize file provider: %v", err)
		}
		factoryLog.Info("Data provider initialized: file")
		return provider, nil

	case "http":
		provider, err := NewHTTPProvider(config.Provider.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HTTP provider: %v", err)
		}
		factoryLog.Info("Data provider initialized: http")
		return provider, nil

	default:
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
}