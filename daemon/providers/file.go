package providers

import (
	"fmt"
	"os"
	"sync"
	"time"

	"p0_agent_daemon/config"
	"p0_agent_daemon/logging"

	"gopkg.in/yaml.v3"
)

type FileProvider struct {
	config      *Config
	configMu    sync.RWMutex
	lastModTime time.Time
	ConfigPath  string
}

var fileLog = logging.NewLogger("file-provider")

func NewFileProvider(configPath string) *FileProvider {
	return &FileProvider{
		ConfigPath: configPath,
	}
}

func (fp *FileProvider) Reload() error {
	fp.configMu.Lock()
	defer fp.configMu.Unlock()

	if _, err := os.Stat(fp.ConfigPath); os.IsNotExist(err) {
		fileLog.Warn("Config file not found at %s, using empty configuration", fp.ConfigPath)
		fp.config = &Config{
			Provider:   ProviderConfig{Type: "file"},
			Users:      map[string]ConfigUser{},
			Sudoers:    []string{},
			DenyUsers:  []string{},
			DenyGroups: []string{},
			DenyUids:   []int{},
			DenyGids:   []int{},
			LogLevel:   "info",
		}
		return nil
	}

	fileInfo, err := os.Stat(fp.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(fp.lastModTime) {
		return nil
	}

	data, err := os.ReadFile(fp.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config YAML: %v", err)
	}

	if config.Provider.Type == "" {
		config.Provider.Type = "file"
	}

	fp.config = &config
	fp.lastModTime = fileInfo.ModTime()

	fileLog.Info("Loaded configuration from %s", fp.ConfigPath)
	return nil
}

func (fp *FileProvider) GetUser(username string) (*User, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
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

	switch groupname {
	case config.P0AgentAdminGroup:
		return &Group{
			Name:    config.P0AgentAdminGroup,
			GID:     config.P0AgentAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	case config.P0AgentUserGroup:
		return &Group{
			Name:    config.P0AgentUserGroup,
			GID:     config.P0AgentUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	}

	if configUser, exists := fp.config.Users[groupname]; exists {
		return &Group{
			Name:    groupname,
			GID:     configUser.GID,
			Members: []string{groupname}, // Group contains the user with same name
		}, nil
	}

	return nil, fmt.Errorf("group not found")
}

func (fp *FileProvider) GetGroupByGID(gid int) (*Group, error) {
	fp.configMu.RLock()
	defer fp.configMu.RUnlock()

	if fp.config == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	switch gid {
	case config.P0AgentAdminGID:
		return &Group{
			Name:    config.P0AgentAdminGroup,
			GID:     config.P0AgentAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	case config.P0AgentUserGID:
		return &Group{
			Name:    config.P0AgentUserGroup,
			GID:     config.P0AgentUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	}

	for username, configUser := range fp.config.Users {
		if configUser.GID == gid {
			return &Group{
				Name:    username,
				GID:     configUser.GID,
				Members: []string{username}, // Group contains the user with same name
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

	groups = append(groups, &Group{
		Name:    config.P0AgentAdminGroup,
		GID:     config.P0AgentAdminGID,
		Members: []string{}, // Members are determined dynamically via InitGroups
	})

	groups = append(groups, &Group{
		Name:    config.P0AgentUserGroup,
		GID:     config.P0AgentUserGID,
		Members: []string{}, // Members are determined dynamically via InitGroups
	})

	for username, configUser := range fp.config.Users {
		groups = append(groups, &Group{
			Name:    username,
			GID:     configUser.GID,
			Members: []string{username}, // Group contains the user with same name
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

	configUser, exists := fp.config.Users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	var groups []int

	groups = append(groups, configUser.GID)

	for _, sudoer := range fp.config.Sudoers {
		if sudoer == username {
			adminGid := config.P0AgentAdminGID
			found := false
			for _, gid := range groups {
				if gid == adminGid {
					found = true
					break
				}
			}
			if !found {
				groups = append(groups, adminGid)
				fileLog.Debug("Added p0-agent-admin group (GID %d) for sudoer user %s", adminGid, username)
			}
			break
		}
	}

	userGid := config.P0AgentUserGID
	found := false
	for _, gid := range groups {
		if gid == userGid {
			found = true
			break
		}
	}
	if !found {
		groups = append(groups, userGid)
		fileLog.Debug("Added p0-agent-user group (GID %d) for user %s", userGid, username)
	}

	return groups, nil
}
