package providers

import (
	"fmt"
	"os"

	"p0_agent_daemon/logging"

	"gopkg.in/yaml.v3"
)

var factoryLog = logging.NewLogger("factory")

func InitializeProvider(configPath string) (DataProvider, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		factoryLog.Warn("Config file not found at %s, using file provider with defaults", configPath)
		return NewFileProvider(configPath), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %v", err)
	}

	providerType := config.Provider.Type
	if providerType == "" {
		providerType = "file"
	}

	switch providerType {
	case "file":
		provider := NewFileProvider(configPath)
		if err := provider.Reload(); err != nil {
			return nil, fmt.Errorf("failed to initialize file provider: %v", err)
		}
		factoryLog.Info("Data provider initialized: file")
		return provider, nil

	case "http":
		httpProvider, err := NewHTTPProvider(&config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HTTP provider: %v", err)
		}

		// Get cache TTL from the HTTP provider's structured config
		cacheTTL := httpProvider.GetCacheTTL()
		
		provider := NewCacheProvider(httpProvider, cacheTTL)
		factoryLog.Info("Data provider initialized: http with cache (TTL: %v)", cacheTTL)
		return provider, nil

	default:
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
}
