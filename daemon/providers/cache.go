package providers

import (
	"fmt"
	"sync"
	"time"

	"p0_agent_daemon/logging"
)

type cacheEntry struct {
	data      interface{}
	timestamp time.Time
	ttl       time.Duration
}

func (ce *cacheEntry) isExpired() bool {
	return time.Since(ce.timestamp) > ce.ttl
}

var cacheLog = logging.NewLogger("cache-provider")

type CacheProvider struct {
	provider   DataProvider
	cache      map[string]*cacheEntry
	cacheMu    sync.RWMutex
	defaultTTL time.Duration
}

func NewCacheProvider(provider DataProvider, defaultTTL time.Duration) *CacheProvider {
	if defaultTTL == 0 {
		defaultTTL = 10 * time.Second // 10 second default
	}

	cp := &CacheProvider{
		provider:   provider,
		cache:      make(map[string]*cacheEntry),
		defaultTTL: defaultTTL,
	}

	cacheLog.Info("Cache provider initialized with TTL: %v", defaultTTL)
	return cp
}

func (cp *CacheProvider) getCached(key string) (interface{}, bool) {
	cp.cacheMu.RLock()
	defer cp.cacheMu.RUnlock()

	if entry, exists := cp.cache[key]; exists && !entry.isExpired() {
		cacheLog.Debug("Cache hit for key: %s", key)
		return entry.data, true
	}

	cacheLog.Debug("Cache miss for key: %s", key)
	return nil, false
}

func (cp *CacheProvider) setCache(key string, data interface{}, ttl time.Duration) {
	cp.cacheMu.Lock()
	defer cp.cacheMu.Unlock()

	if ttl == 0 {
		ttl = cp.defaultTTL
	}

	cp.cache[key] = &cacheEntry{
		data:      data,
		timestamp: time.Now(),
		ttl:       ttl,
	}

	cacheLog.Debug("Cached data for key: %s (TTL: %v)", key, ttl)
}

func (cp *CacheProvider) clearCache() {
	cp.cacheMu.Lock()
	defer cp.cacheMu.Unlock()

	cp.cache = make(map[string]*cacheEntry)
	cacheLog.Info("Cache cleared")
}

func (cp *CacheProvider) GetUser(username string) (*User, error) {
	cacheKey := fmt.Sprintf("user:%s", username)

	if cached, found := cp.getCached(cacheKey); found {
		if user, ok := cached.(*User); ok {
			return user, nil
		}
	}

	user, err := cp.provider.GetUser(username)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, user, 0)
	return user, nil
}

func (cp *CacheProvider) GetUserByUID(uid int) (*User, error) {
	cacheKey := fmt.Sprintf("user_by_uid:%d", uid)

	if cached, found := cp.getCached(cacheKey); found {
		if user, ok := cached.(*User); ok {
			return user, nil
		}
	}

	user, err := cp.provider.GetUserByUID(uid)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, user, 0)
	return user, nil
}

func (cp *CacheProvider) GetGroup(groupname string) (*Group, error) {
	cacheKey := fmt.Sprintf("group:%s", groupname)

	if cached, found := cp.getCached(cacheKey); found {
		if group, ok := cached.(*Group); ok {
			return group, nil
		}
	}

	group, err := cp.provider.GetGroup(groupname)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, group, 0)
	return group, nil
}

func (cp *CacheProvider) GetGroupByGID(gid int) (*Group, error) {
	cacheKey := fmt.Sprintf("group_by_gid:%d", gid)

	if cached, found := cp.getCached(cacheKey); found {
		if group, ok := cached.(*Group); ok {
			return group, nil
		}
	}

	group, err := cp.provider.GetGroupByGID(gid)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, group, 0)
	return group, nil
}

func (cp *CacheProvider) GetKeys(username string) ([]string, error) {
	cacheKey := fmt.Sprintf("keys:%s", username)

	if cached, found := cp.getCached(cacheKey); found {
		if keys, ok := cached.([]string); ok {
			return keys, nil
		}
	}

	keys, err := cp.provider.GetKeys(username)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, keys, 0)
	return keys, nil
}

func (cp *CacheProvider) ListUsers() ([]*User, error) {
	cacheKey := "list_users"

	if cached, found := cp.getCached(cacheKey); found {
		if users, ok := cached.([]*User); ok {
			return users, nil
		}
	}

	users, err := cp.provider.ListUsers()
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, users, 0)
	return users, nil
}

func (cp *CacheProvider) ListGroups() ([]*Group, error) {
	cacheKey := "list_groups"

	if cached, found := cp.getCached(cacheKey); found {
		if groups, ok := cached.([]*Group); ok {
			return groups, nil
		}
	}

	groups, err := cp.provider.ListGroups()
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, groups, 0)
	return groups, nil
}

func (cp *CacheProvider) CheckSudo(username string) (bool, error) {
	cacheKey := fmt.Sprintf("sudo:%s", username)

	if cached, found := cp.getCached(cacheKey); found {
		if result, ok := cached.(bool); ok {
			return result, nil
		}
	}

	result, err := cp.provider.CheckSudo(username)
	if err != nil {
		return false, err
	}

	cp.setCache(cacheKey, result, cp.defaultTTL/2)
	return result, nil
}

func (cp *CacheProvider) InitGroups(username string) ([]int, error) {
	cacheKey := fmt.Sprintf("initgroups:%s", username)

	if cached, found := cp.getCached(cacheKey); found {
		if groups, ok := cached.([]int); ok {
			return groups, nil
		}
	}

	groups, err := cp.provider.InitGroups(username)
	if err != nil {
		return nil, err
	}

	cp.setCache(cacheKey, groups, 0)
	return groups, nil
}

func (cp *CacheProvider) CheckRegistration() (*RegistrationStatus, error) {
	// Registration checks should never be cached - always hit the provider directly
	// for real-time registration status
	return cp.provider.CheckRegistration()
}

func (cp *CacheProvider) Reload() error {
	cp.clearCache()

	return cp.provider.Reload()
}
