package providers

type Config struct {
	Provider   ProviderConfig        `yaml:"provider"`
	Users      map[string]ConfigUser `yaml:"users"`
	Sudoers    []string              `yaml:"sudoers"`
	DenyUsers  []string              `yaml:"deny_users"`
	DenyGroups []string              `yaml:"deny_groups"`
	DenyUids   []int                 `yaml:"deny_uids"`
	DenyGids   []int                 `yaml:"deny_gids"`
	LogLevel   string                `yaml:"log_level"`
	Cache      CacheConfig           `yaml:"cache"`
}

type ProviderConfig struct {
	Type        string                 `yaml:"type"`        // "file", "http", etc.
	Environment string                 `yaml:"environment"` // Environment ID for registration (default: "default")
	Config      map[string]interface{} `yaml:"config,omitempty"`
}

type ConfigUser struct {
	UID   int      `yaml:"uid"`
	GID   int      `yaml:"gid"`
	Gecos string   `yaml:"gecos,omitempty"`
	Dir   string   `yaml:"dir,omitempty"`
	Shell string   `yaml:"shell,omitempty"`
	Keys  []string `yaml:"keys,omitempty"`
}

type ConfigGroup struct {
	GID     int      `yaml:"gid"`
	Members []string `yaml:"members,omitempty"`
}

type CacheConfig struct {
	Enabled         bool `yaml:"enabled"`          // Enable cache population (default: true)
	RefreshInterval int  `yaml:"refresh_interval"` // Hours between full cache refresh (default: 24)
	OnDemandUpdate  bool `yaml:"on_demand_update"` // Update cache when users accessed via socket (default: true)
}
