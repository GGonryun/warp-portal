package providers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"warp_portal_daemon/logging"
)

var cacheLogger = logging.NewLogger("cache-manager")

const (
	DefaultCacheDirectory  = "/var/cache/warp_portal"
	DefaultRefreshInterval = 24 // hours
	PasswdCacheFile        = "passwd.cache"
	GroupCacheFile         = "group.cache"
)

type CacheManager struct {
	config         *Config
	provider       DataProvider
	cacheDirectory string
	refreshTicker  *time.Ticker
	stopChan       chan struct{}
	mutex          sync.RWMutex
	lastRefresh    time.Time
}

func NewCacheManager(config *Config, provider DataProvider) (*CacheManager, error) {
	cacheConfig := &config.Cache
	if cacheConfig.CacheDirectory == "" {
		cacheConfig.CacheDirectory = DefaultCacheDirectory
	}
	if cacheConfig.RefreshInterval == 0 {
		cacheConfig.RefreshInterval = DefaultRefreshInterval
	}
	if !cacheConfig.Enabled {
		cacheConfig.Enabled = true
	}
	if !cacheConfig.OnDemandUpdate {
		cacheConfig.OnDemandUpdate = true
	}

	cm := &CacheManager{
		config:         config,
		provider:       provider,
		cacheDirectory: cacheConfig.CacheDirectory,
		stopChan:       make(chan struct{}),
	}

	if err := os.MkdirAll(cm.cacheDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory %s: %w", cm.cacheDirectory, err)
	}

	cacheLogger.Info("Cache manager initialized with directory: %s, refresh interval: %d hours",
		cm.cacheDirectory, cacheConfig.RefreshInterval)

	return cm, nil
}

func (cm *CacheManager) Start() error {
	if !cm.config.Cache.Enabled {
		cacheLogger.Info("Cache is disabled, not starting cache manager")
		return nil
	}

	if err := cm.RefreshCache(); err != nil {
		cacheLogger.Error("Initial cache population failed: %v", err)
	}

	refreshInterval := time.Duration(cm.config.Cache.RefreshInterval) * time.Hour
	cm.refreshTicker = time.NewTicker(refreshInterval)

	go func() {
		for {
			select {
			case <-cm.refreshTicker.C:
				if err := cm.RefreshCache(); err != nil {
					cacheLogger.Error("Scheduled cache refresh failed: %v", err)
				}
			case <-cm.stopChan:
				return
			}
		}
	}()

	cacheLogger.Info("Cache manager started with %d hour refresh interval", cm.config.Cache.RefreshInterval)
	return nil
}

func (cm *CacheManager) Stop() {
	if cm.refreshTicker != nil {
		cm.refreshTicker.Stop()
	}
	close(cm.stopChan)
	cacheLogger.Info("Cache manager stopped")
}

func (cm *CacheManager) RefreshCache() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cacheLogger.Info("Starting full cache refresh")
	start := time.Now()

	if err := cm.refreshUsersCache(); err != nil {
		return fmt.Errorf("failed to refresh users cache: %w", err)
	}

	if err := cm.refreshGroupsCache(); err != nil {
		return fmt.Errorf("failed to refresh groups cache: %w", err)
	}

	cm.lastRefresh = time.Now()
	duration := time.Since(start)
	cacheLogger.Info("Cache refresh completed in %v", duration)

	return nil
}

func (cm *CacheManager) refreshUsersCache() error {
	users, err := cm.provider.ListUsers()
	if err != nil {
		return fmt.Errorf("failed to list users from provider: %w", err)
	}

	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)
	tmpFile := passwdFile + ".tmp"

	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp passwd cache file: %w", err)
	}
	defer f.Close()

	count := 0
	for _, user := range users {
		line := fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n",
			user.Name, user.UID, user.GID, user.Gecos, user.Dir, user.Shell)

		if _, err := f.WriteString(line); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to write user %s to cache: %w", user.Name, err)
		}
		count++
	}

	if err := f.Sync(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to sync passwd cache file: %w", err)
	}

	if err := os.Rename(tmpFile, passwdFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename passwd cache file: %w", err)
	}

	cacheLogger.Debug("Refreshed passwd cache with %d users", count)
	return nil
}

func (cm *CacheManager) refreshGroupsCache() error {
	groups, err := cm.provider.ListGroups()
	if err != nil {
		return fmt.Errorf("failed to list groups from provider: %w", err)
	}

	groupFile := filepath.Join(cm.cacheDirectory, GroupCacheFile)
	tmpFile := groupFile + ".tmp"

	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp group cache file: %w", err)
	}
	defer f.Close()

	count := 0
	for _, group := range groups {
		// Format: groupname:x:gid:member1,member2,member3
		members := strings.Join(group.Members, ",")
		line := fmt.Sprintf("%s:x:%d:%s\n", group.Name, group.GID, members)

		if _, err := f.WriteString(line); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to write group %s to cache: %w", group.Name, err)
		}
		count++
	}

	if err := f.Sync(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to sync group cache file: %w", err)
	}

	if err := os.Rename(tmpFile, groupFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename group cache file: %w", err)
	}

	cacheLogger.Debug("Refreshed group cache with %d groups", count)
	return nil
}

func (cm *CacheManager) AddUserToCache(user *User) error {
	if !cm.config.Cache.Enabled || !cm.config.Cache.OnDemandUpdate {
		return nil
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)

	if cm.userExistsInCache(user.Name) {
		cacheLogger.Debug("User %s already exists in cache", user.Name)
		return nil
	}

	f, err := os.OpenFile(passwdFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open passwd cache file: %w", err)
	}
	defer f.Close()

	line := fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n",
		user.Name, user.UID, user.GID, user.Gecos, user.Dir, user.Shell)

	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("failed to add user %s to cache: %w", user.Name, err)
	}

	cacheLogger.Info("Added user %s to cache", user.Name)
	return nil
}

func (cm *CacheManager) userExistsInCache(username string) bool {
	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)

	content, err := os.ReadFile(passwdFile)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, username+":") {
			return true
		}
	}

	return false
}

func (cm *CacheManager) GetCacheStatus() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	status := map[string]interface{}{
		"enabled":          cm.config.Cache.Enabled,
		"cache_directory":  cm.cacheDirectory,
		"refresh_interval": cm.config.Cache.RefreshInterval,
		"on_demand_update": cm.config.Cache.OnDemandUpdate,
		"last_refresh":     cm.lastRefresh.Format(time.RFC3339),
	}

	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)
	if stat, err := os.Stat(passwdFile); err == nil {
		status["passwd_cache_size"] = stat.Size()
		status["passwd_cache_modified"] = stat.ModTime().Format(time.RFC3339)
	}

	groupFile := filepath.Join(cm.cacheDirectory, GroupCacheFile)
	if stat, err := os.Stat(groupFile); err == nil {
		status["group_cache_size"] = stat.Size()
		status["group_cache_modified"] = stat.ModTime().Format(time.RFC3339)
	}

	return status
}
