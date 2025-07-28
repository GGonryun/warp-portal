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
	DefaultCacheDirectory  = "/tmp/warp_portal"
	DefaultRefreshInterval = 8 // hours
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
	cacheLogger.Trace("Creating new cache manager...")

	cacheConfig := &config.Cache
	if cacheConfig.RefreshInterval == 0 {
		cacheLogger.Trace("Using default refresh interval: %d hours", DefaultRefreshInterval)
		cacheConfig.RefreshInterval = DefaultRefreshInterval
	}
	if cacheConfig.Enabled {
		if !cacheConfig.OnDemandUpdate {
			cacheLogger.Trace("Defaulting on-demand updates to enabled")
			cacheConfig.OnDemandUpdate = true
		}
	} else {
		cacheLogger.Info("Cache is disabled in configuration")
	}

	cacheLogger.Trace("Cache configuration: enabled=%t, directory=%s, refresh_interval=%d hours, on_demand=%t",
		cacheConfig.Enabled, DefaultCacheDirectory, cacheConfig.RefreshInterval, cacheConfig.OnDemandUpdate)

	cm := &CacheManager{
		config:         config,
		provider:       provider,
		cacheDirectory: DefaultCacheDirectory,
		stopChan:       make(chan struct{}),
	}

	if cacheConfig.Enabled {
		cacheLogger.Trace("Creating cache directory with permissions 0755: %s", cm.cacheDirectory)
		if err := os.MkdirAll(cm.cacheDirectory, 0755); err != nil {
			cacheLogger.Error("Failed to create cache directory %s: %v", cm.cacheDirectory, err)
			return nil, fmt.Errorf("failed to create cache directory %s: %w", cm.cacheDirectory, err)
		}

		if err := os.Chmod(cm.cacheDirectory, 0755); err != nil {
			cacheLogger.Warn("Failed to set permissions on cache directory %s: %v", cm.cacheDirectory, err)
		}

		cacheLogger.Trace("Initializing cache files if they don't exist")
		if err := cm.initializeCacheFiles(); err != nil {
			cacheLogger.Warn("Failed to initialize cache files: %v", err)
		}
	} else {
		cacheLogger.Debug("Skipping cache directory and file initialization (cache disabled)")
	}

	cacheLogger.Info("Cache manager initialized with directory: %s, refresh interval: %d hours",
		cm.cacheDirectory, cacheConfig.RefreshInterval)

	return cm, nil
}

func (cm *CacheManager) initializeCacheFiles() error {
	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)
	groupFile := filepath.Join(cm.cacheDirectory, GroupCacheFile)

	if _, err := os.Stat(passwdFile); os.IsNotExist(err) {
		cacheLogger.Trace("Creating empty passwd cache file: %s", passwdFile)
		f, err := os.OpenFile(passwdFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to create passwd cache file: %w", err)
		}
		f.Close()
		cacheLogger.Debug("Created empty passwd cache file: %s", passwdFile)
	} else {
		cacheLogger.Trace("Passwd cache file already exists: %s", passwdFile)
	}

	if _, err := os.Stat(groupFile); os.IsNotExist(err) {
		cacheLogger.Trace("Creating empty group cache file: %s", groupFile)
		f, err := os.OpenFile(groupFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to create group cache file: %w", err)
		}
		f.Close()
		cacheLogger.Debug("Created empty group cache file: %s", groupFile)
	} else {
		cacheLogger.Trace("Group cache file already exists: %s", groupFile)
	}

	return nil
}

func (cm *CacheManager) Start() error {
	cacheLogger.Trace("Starting cache manager...")

	if !cm.config.Cache.Enabled {
		cacheLogger.Info("Cache is disabled, not starting cache manager")
		return nil
	}

	cacheLogger.Trace("Performing initial cache population...")
	if err := cm.RefreshCache(); err != nil {
		cacheLogger.Error("Initial cache population failed: %v", err)
	} else {
		cacheLogger.Trace("Initial cache population completed successfully")
	}

	refreshInterval := time.Duration(cm.config.Cache.RefreshInterval) * time.Hour
	cacheLogger.Trace("Setting up refresh ticker with interval: %v", refreshInterval)
	cm.refreshTicker = time.NewTicker(refreshInterval)

	go func() {
		cacheLogger.Trace("Cache refresh goroutine started")
		for {
			select {
			case <-cm.refreshTicker.C:
				cacheLogger.Trace("Ticker triggered scheduled cache refresh")
				if err := cm.RefreshCache(); err != nil {
					cacheLogger.Error("Scheduled cache refresh failed: %v", err)
				} else {
					cacheLogger.Trace("Scheduled cache refresh completed successfully")
				}
			case <-cm.stopChan:
				cacheLogger.Trace("Cache refresh goroutine received stop signal")
				return
			}
		}
	}()

	cacheLogger.Info("Cache manager started with %d hour refresh interval", cm.config.Cache.RefreshInterval)
	return nil
}

func (cm *CacheManager) Stop() {
	cacheLogger.Trace("Stopping cache manager...")

	if cm.refreshTicker != nil {
		cacheLogger.Trace("Stopping refresh ticker")
		cm.refreshTicker.Stop()
	}

	cacheLogger.Trace("Closing stop channel")
	close(cm.stopChan)

	cacheLogger.Info("Cache manager stopped")
}

func (cm *CacheManager) RefreshCache() error {
	cacheLogger.Trace("Acquiring cache mutex lock for full refresh")
	cm.mutex.Lock()
	defer func() {
		cm.mutex.Unlock()
		cacheLogger.Trace("Released cache mutex lock")
	}()

	cacheLogger.Info("Starting full cache refresh")
	start := time.Now()

	cacheLogger.Trace("Refreshing users cache...")
	if err := cm.refreshUsersCache(); err != nil {
		cacheLogger.Error("Users cache refresh failed: %v", err)
		return fmt.Errorf("failed to refresh users cache: %w", err)
	}
	cacheLogger.Trace("Users cache refresh completed")

	cacheLogger.Trace("Refreshing groups cache...")
	if err := cm.refreshGroupsCache(); err != nil {
		cacheLogger.Error("Groups cache refresh failed: %v", err)
		return fmt.Errorf("failed to refresh groups cache: %w", err)
	}
	cacheLogger.Trace("Groups cache refresh completed")

	cm.lastRefresh = time.Now()
	duration := time.Since(start)
	cacheLogger.Info("Cache refresh completed in %v", duration)
	cacheLogger.Trace("Last refresh timestamp updated to: %s", cm.lastRefresh.Format(time.RFC3339))

	return nil
}

func (cm *CacheManager) refreshUsersCache() error {
	cacheLogger.Trace("Listing users from provider...")
	users, err := cm.provider.ListUsers()
	if err != nil {
		cacheLogger.Error("Failed to list users from provider: %v", err)
		return fmt.Errorf("failed to list users from provider: %w", err)
	}
	cacheLogger.Trace("Retrieved %d users from provider", len(users))

	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)
	tmpFile := passwdFile + ".tmp"
	cacheLogger.Trace("Creating temporary passwd cache file: %s", tmpFile)

	f, err := os.Create(tmpFile)
	if err != nil {
		cacheLogger.Error("Failed to create temp passwd cache file: %v", err)
		return fmt.Errorf("failed to create temp passwd cache file: %w", err)
	}
	defer f.Close()

	count := 0
	for _, user := range users {
		line := fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n",
			user.Name, user.UID, user.GID, user.Gecos, user.Dir, user.Shell)

		cacheLogger.Trace("Writing user to cache: %s (UID: %d)", user.Name, user.UID)
		if _, err := f.WriteString(line); err != nil {
			cacheLogger.Error("Failed to write user %s to cache: %v", user.Name, err)
			os.Remove(tmpFile)
			return fmt.Errorf("failed to write user %s to cache: %w", user.Name, err)
		}
		count++
	}

	cacheLogger.Trace("Syncing passwd cache file to disk")
	if err := f.Sync(); err != nil {
		cacheLogger.Error("Failed to sync passwd cache file: %v", err)
		os.Remove(tmpFile)
		return fmt.Errorf("failed to sync passwd cache file: %w", err)
	}

	cacheLogger.Trace("Atomically replacing passwd cache file: %s -> %s", tmpFile, passwdFile)
	if err := os.Rename(tmpFile, passwdFile); err != nil {
		cacheLogger.Error("Failed to rename passwd cache file: %v", err)
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename passwd cache file: %w", err)
	}

	cacheLogger.Debug("Refreshed passwd cache with %d users", count)
	return nil
}

func (cm *CacheManager) refreshGroupsCache() error {
	cacheLogger.Trace("Listing groups from provider...")
	groups, err := cm.provider.ListGroups()
	if err != nil {
		cacheLogger.Error("Failed to list groups from provider: %v", err)
		return fmt.Errorf("failed to list groups from provider: %w", err)
	}
	cacheLogger.Trace("Retrieved %d groups from provider", len(groups))

	groupFile := filepath.Join(cm.cacheDirectory, GroupCacheFile)
	tmpFile := groupFile + ".tmp"
	cacheLogger.Trace("Creating temporary group cache file: %s", tmpFile)

	f, err := os.Create(tmpFile)
	if err != nil {
		cacheLogger.Error("Failed to create temp group cache file: %v", err)
		return fmt.Errorf("failed to create temp group cache file: %w", err)
	}
	defer f.Close()

	count := 0
	for _, group := range groups {
		// Format: groupname:x:gid:member1,member2,member3
		members := strings.Join(group.Members, ",")
		line := fmt.Sprintf("%s:x:%d:%s\n", group.Name, group.GID, members)

		cacheLogger.Trace("Writing group to cache: %s (GID: %d) with %d members", group.Name, group.GID, len(group.Members))
		if _, err := f.WriteString(line); err != nil {
			cacheLogger.Error("Failed to write group %s to cache: %v", group.Name, err)
			os.Remove(tmpFile)
			return fmt.Errorf("failed to write group %s to cache: %w", group.Name, err)
		}
		count++
	}

	cacheLogger.Trace("Syncing group cache file to disk")
	if err := f.Sync(); err != nil {
		cacheLogger.Error("Failed to sync group cache file: %v", err)
		os.Remove(tmpFile)
		return fmt.Errorf("failed to sync group cache file: %w", err)
	}

	cacheLogger.Trace("Atomically replacing group cache file: %s -> %s", tmpFile, groupFile)
	if err := os.Rename(tmpFile, groupFile); err != nil {
		cacheLogger.Error("Failed to rename group cache file: %v", err)
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename group cache file: %w", err)
	}

	cacheLogger.Debug("Refreshed group cache with %d groups", count)
	return nil
}

func (cm *CacheManager) AddUserToCache(user *User) error {
	cacheLogger.Trace("Request to add user %s to cache", user.Name)

	if !cm.config.Cache.Enabled || !cm.config.Cache.OnDemandUpdate {
		cacheLogger.Trace("Cache disabled or on-demand updates disabled, skipping user addition")
		return nil
	}

	cacheLogger.Trace("Acquiring cache mutex lock for on-demand user addition")
	cm.mutex.Lock()
	defer func() {
		cm.mutex.Unlock()
		cacheLogger.Trace("Released cache mutex lock")
	}()

	passwdFile := filepath.Join(cm.cacheDirectory, PasswdCacheFile)
	cacheLogger.Trace("Checking if user %s already exists in cache", user.Name)

	if cm.userExistsInCache(user.Name) {
		cacheLogger.Debug("User %s already exists in cache, skipping addition", user.Name)
		return nil
	}

	cacheLogger.Trace("Opening passwd cache file for append: %s", passwdFile)
	f, err := os.OpenFile(passwdFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		cacheLogger.Error("Failed to open passwd cache file: %v", err)
		return fmt.Errorf("failed to open passwd cache file: %w", err)
	}
	defer f.Close()

	line := fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n",
		user.Name, user.UID, user.GID, user.Gecos, user.Dir, user.Shell)

	cacheLogger.Trace("Writing user entry to cache: %s", strings.TrimSpace(line))
	if _, err := f.WriteString(line); err != nil {
		cacheLogger.Error("Failed to add user %s to cache: %v", user.Name, err)
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
		"cache_directory":  DefaultCacheDirectory,
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
