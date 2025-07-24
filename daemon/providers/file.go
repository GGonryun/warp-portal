package providers

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"warp_portal_daemon/logging"
	"gopkg.in/yaml.v3"
)


// File-based data provider implementation
type FileProvider struct {
	config      *Config
	configMu    sync.RWMutex
	lastModTime time.Time
	ConfigPath  string
}

// File provider logger
var fileLog = logging.NewLogger("file-provider")

func NewFileProvider(configPath string) *FileProvider {
	return &FileProvider{
		ConfigPath: configPath,
	}
}

func (fp *FileProvider) Reload() error {
	fp.configMu.Lock()
	defer fp.configMu.Unlock()

	// Check if file exists
	if _, err := os.Stat(fp.ConfigPath); os.IsNotExist(err) {
		fileLog.Warn("Config file not found at %s, using empty configuration", fp.ConfigPath)
		fp.config = &Config{
			Provider:   ProviderConfig{Type: "file"},
			Users:      map[string]ConfigUser{},
			Groups:     map[string]ConfigGroup{},
			Sudoers:    []string{},
			DenyUsers:  []string{},
			DenyGroups: []string{},
			LogLevel:   "info",
		}
		return nil
	}

	// Check modification time to avoid unnecessary reloads
	fileInfo, err := os.Stat(fp.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(fp.lastModTime) {
		return nil // File hasn't changed
	}

	data, err := os.ReadFile(fp.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config YAML: %v", err)
	}

	// Default provider type if not specified
	if config.Provider.Type == "" {
		config.Provider.Type = "file"
	}

	fp.config = &config
	fp.lastModTime = fileInfo.ModTime()

	fileLog.Info("Loaded configuration from %s", fp.ConfigPath)
	return nil
}

func (fp *FileProvider) isUserDenied(username string) bool {
	for _, deniedUser := range fp.config.DenyUsers {
		if deniedUser == username {
			return true
		}
	}
	return false
}

func (fp *FileProvider) isGroupDenied(groupname string) bool {
	for _, deniedGroup := range fp.config.DenyGroups {
		if deniedGroup == groupname {
			return true
		}
	}
	return false
}

func (fp *FileProvider) GetUser(username string) (*User, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	// Check deny list first
	if fp.isUserDenied(username) {
		return nil, fmt.Errorf("user explicitly denied")
	}

	configUser, exists := fp.config.Users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return &User{
		Name:  username,
		UID:   configUser.UID,
		GID:   configUser.GID,
		Gecos: configUser.Gecos,
		Dir:   configUser.Dir,
		Shell: configUser.Shell,
	}, nil
}

func (fp *FileProvider) GetUserByUID(uid int) (*User, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	for username, configUser := range fp.config.Users {
		if configUser.UID == uid {
			return &User{
				Name:  username,
				UID:   configUser.UID,
				GID:   configUser.GID,
				Gecos: configUser.Gecos,
				Dir:   configUser.Dir,
				Shell: configUser.Shell,
			}, nil
		}
	}

	return nil, fmt.Errorf("user with UID %d not found", uid)
}

func (fp *FileProvider) GetGroup(groupname string) (*Group, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	// Check deny list first
	if fp.isGroupDenied(groupname) {
		return nil, fmt.Errorf("group explicitly denied")
	}

	configGroup, exists := fp.config.Groups[groupname]
	if !exists {
		return nil, fmt.Errorf("group not found")
	}

	return &Group{
		Name:    groupname,
		GID:     configGroup.GID,
		Members: configGroup.Members,
	}, nil
}

func (fp *FileProvider) GetGroupByGID(gid int) (*Group, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	for groupname, configGroup := range fp.config.Groups {
		if configGroup.GID == gid {
			return &Group{
				Name:    groupname,
				GID:     configGroup.GID,
				Members: configGroup.Members,
			}, nil
		}
	}

	return nil, fmt.Errorf("group with GID %d not found", gid)
}

func (fp *FileProvider) GetKeys(username string) ([]string, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	configUser, exists := fp.config.Users[username]
	if !exists || len(configUser.Keys) == 0 {
		return nil, fmt.Errorf("no SSH keys found for user")
	}

	return configUser.Keys, nil
}

func (fp *FileProvider) ListUsers() ([]*User, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	var users []*User
	for username, configUser := range fp.config.Users {
		users = append(users, &User{
			Name:  username,
			UID:   configUser.UID,
			GID:   configUser.GID,
			Gecos: configUser.Gecos,
			Dir:   configUser.Dir,
			Shell: configUser.Shell,
		})
	}

	return users, nil
}

func (fp *FileProvider) ListGroups() ([]*Group, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	var groups []*Group
	for groupname, configGroup := range fp.config.Groups {
		groups = append(groups, &Group{
			Name:    groupname,
			GID:     configGroup.GID,
			Members: configGroup.Members,
		})
	}

	return groups, nil
}

func (fp *FileProvider) CheckSudo(username string) (bool, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return false, fmt.Errorf("configuration not loaded")
	}

	// Check if user is in the dedicated sudoers list
	for _, sudoer := range fp.config.Sudoers {
		if sudoer == username {
			return true, nil
		}
	}

	return false, nil
}

func (fp *FileProvider) InitGroups(username string) ([]int, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	// Check if user exists
	configUser, exists := fp.config.Users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	var groups []int

	// Find all groups where this user is a member
	for _, configGroup := range fp.config.Groups {
		for _, member := range configGroup.Members {
			if member == username {
				groups = append(groups, configGroup.GID)
				break
			}
		}
	}

	// Also include the user's primary group if it's not already in the list
	primaryGroupFound := false
	for _, gid := range groups {
		if gid == configUser.GID {
			primaryGroupFound = true
			break
		}
	}
	if !primaryGroupFound {
		groups = append(groups, configUser.GID)
	}

	// Check if user is in sudoers list and add warp-portal-admin group
	for _, sudoer := range fp.config.Sudoers {
		if sudoer == username {
			// Look up the system group ID for warp-portal-admin
			if adminGroup, err := user.LookupGroup("warp-portal-admin"); err == nil {
				if adminGid, err := strconv.Atoi(adminGroup.Gid); err == nil {
					// Check if we already have this group (avoid duplicates)
					found := false
					for _, gid := range groups {
						if gid == adminGid {
							found = true
							break
						}
					}
					if !found {
						groups = append(groups, adminGid)
						fileLog.Debug("Added warp-portal-admin group (GID %d) for sudoer user %s", adminGid, username)
					}
				} else {
					fileLog.Error("Warning: Failed to parse GID for warp-portal-admin group: %v", err)
				}
			} else {
				fileLog.Error("Warning: warp-portal-admin group not found in system: %v", err)
			}
			break
		}
	}

	return groups, nil
}
