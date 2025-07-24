package providers

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"warp_portal_daemon/config"
	"warp_portal_daemon/logging"
)

// Cache entry for HTTP provider
type cacheEntry struct {
	data      interface{}
	timestamp time.Time
	ttl       time.Duration
}

func (ce *cacheEntry) isExpired() bool {
	return time.Since(ce.timestamp) > ce.ttl
}

// HTTP provider logger
var httpLog = logging.NewLogger("http-provider")

// HTTP Provider implementation
type HTTPProvider struct {
	config       map[string]interface{}
	cache        map[string]*cacheEntry
	cacheMu      sync.RWMutex
	client       *http.Client
	baseURL      string
	fingerprint  string
	defaultTTL   time.Duration
}

// Machine fingerprint generation - returns SSH host key fingerprint
func getMachineFingerprint() (string, error) {
	// Try common SSH host key locations
	hostKeyPaths := []string{
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}
	
	for _, path := range hostKeyPaths {
		if data, err := os.ReadFile(path); err == nil {
			// Generate SHA256 fingerprint similar to SSH
			hash := sha256.Sum256(data)
			fingerprint := "SHA256:" + strings.TrimRight(hex.EncodeToString(hash[:]), "=")
			httpLog.Debug("Generated machine fingerprint from %s: %s", path, fingerprint)
			return fingerprint, nil
		}
	}
	
	// Fallback: use machine hostname + current time hash
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	
	fallbackData := fmt.Sprintf("%s-%d", hostname, time.Now().Unix()/3600) // Changes hourly
	hash := md5.Sum([]byte(fallbackData))
	fingerprint := "MD5:" + hex.EncodeToString(hash[:])
	httpLog.Debug("Generated fallback machine fingerprint: %s", fingerprint)
	return fingerprint, nil
}

func NewHTTPProvider(config map[string]interface{}) (*HTTPProvider, error) {
	hp := &HTTPProvider{
		config: config,
		cache:  make(map[string]*cacheEntry),
	}
	
	// Get base URL
	if url, ok := config["url"].(string); ok {
		hp.baseURL = url
	} else {
		return nil, fmt.Errorf("http provider requires 'url' configuration")
	}
	
	// Get cache TTL (default 300 seconds)
	if ttl, ok := config["cache_ttl"].(int); ok {
		hp.defaultTTL = time.Duration(ttl) * time.Second
	} else {
		hp.defaultTTL = 300 * time.Second
	}
	
	// Get timeout (default 10 seconds)
	timeout := 10 * time.Second
	if t, ok := config["timeout"].(int); ok {
		timeout = time.Duration(t) * time.Second
	}
	
	// Create HTTP client with timeout
	hp.client = &http.Client{
		Timeout: timeout,
	}
	
	// Get machine fingerprint
	var err error
	hp.fingerprint, err = getMachineFingerprint()
	if err != nil {
		httpLog.Error("Failed to get machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}
	
	httpLog.Info("HTTP provider initialized with URL: %s, TTL: %v, Timeout: %v", hp.baseURL, hp.defaultTTL, timeout)
	return hp, nil
}

func (hp *HTTPProvider) makeRequest(endpoint string, params map[string]string) ([]byte, error) {
	url := hp.baseURL + endpoint
	
	// Prepare request payload
	payload := map[string]interface{}{
		"fingerprint": hp.fingerprint,
		"timestamp":   time.Now().Unix(),
	}
	
	// Add parameters
	for k, v := range params {
		payload[k] = v
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	
	httpLog.Debug("Making HTTP request to %s with payload: %s", url, string(jsonData))
	
	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "warp-portal-daemon/1.0")
	
	// Make request
	resp, err := hp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	httpLog.Debug("HTTP request successful, response: %s", string(body))
	return body, nil
}

func (hp *HTTPProvider) getCached(key string) (interface{}, bool) {
	hp.cacheMu.RLock()
	defer hp.cacheMu.RUnlock()
	
	if entry, exists := hp.cache[key]; exists && !entry.isExpired() {
		httpLog.Debug("Cache hit for key: %s", key)
		return entry.data, true
	}
	
	httpLog.Debug("Cache miss for key: %s", key)
	return nil, false
}

func (hp *HTTPProvider) setCache(key string, data interface{}, ttl time.Duration) {
	hp.cacheMu.Lock()
	defer hp.cacheMu.Unlock()
	
	if ttl == 0 {
		ttl = hp.defaultTTL
	}
	
	hp.cache[key] = &cacheEntry{
		data:      data,
		timestamp: time.Now(),
		ttl:       ttl,
	}
	
	httpLog.Debug("Cached data for key: %s (TTL: %v)", key, ttl)
}

func (hp *HTTPProvider) GetUser(username string) (*User, error) {
	cacheKey := fmt.Sprintf("user:%s", username)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if user, ok := cached.(*User); ok {
			return user, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/user", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}
	
	// Parse response
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, &user, 0)
	
	return &user, nil
}

func (hp *HTTPProvider) GetUserByUID(uid int) (*User, error) {
	cacheKey := fmt.Sprintf("user_by_uid:%d", uid)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if user, ok := cached.(*User); ok {
			return user, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/user_by_uid", map[string]string{"uid": strconv.Itoa(uid)})
	if err != nil {
		return nil, err
	}
	
	// Parse response
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, &user, 0)
	
	return &user, nil
}

func (hp *HTTPProvider) GetGroup(groupname string) (*Group, error) {
	// Check for reserved warp-portal groups first
	switch groupname {
	case config.WarpPortalAdminGroup:
		return &Group{
			Name:    config.WarpPortalAdminGroup,
			GID:     config.WarpPortalAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	case config.WarpPortalUserGroup:
		return &Group{
			Name:    config.WarpPortalUserGroup,
			GID:     config.WarpPortalUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	}

	cacheKey := fmt.Sprintf("group:%s", groupname)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if group, ok := cached.(*Group); ok {
			return group, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/group", map[string]string{"groupname": groupname})
	if err != nil {
		return nil, err
	}
	
	// Parse response
	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, &group, 0)
	
	return &group, nil
}

func (hp *HTTPProvider) GetGroupByGID(gid int) (*Group, error) {
	// Check for reserved warp-portal groups first
	switch gid {
	case config.WarpPortalAdminGID:
		return &Group{
			Name:    config.WarpPortalAdminGroup,
			GID:     config.WarpPortalAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	case config.WarpPortalUserGID:
		return &Group{
			Name:    config.WarpPortalUserGroup,
			GID:     config.WarpPortalUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		}, nil
	}

	cacheKey := fmt.Sprintf("group_by_gid:%d", gid)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if group, ok := cached.(*Group); ok {
			return group, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/group_by_gid", map[string]string{"gid": strconv.Itoa(gid)})
	if err != nil {
		return nil, err
	}
	
	// Parse response
	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, &group, 0)
	
	return &group, nil
}

func (hp *HTTPProvider) GetKeys(username string) ([]string, error) {
	cacheKey := fmt.Sprintf("keys:%s", username)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if keys, ok := cached.([]string); ok {
			return keys, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/keys", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}
	
	// Parse response - handle both array format and object format
	var keys []string
	if err := json.Unmarshal(body, &keys); err != nil {
		// Try object format
		var response struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse keys response: %v", err)
		}
		keys = response.Keys
	}
	
	// Cache result
	hp.setCache(cacheKey, keys, 0)
	
	return keys, nil
}

func (hp *HTTPProvider) ListUsers() ([]*User, error) {
	cacheKey := "list_users"
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if users, ok := cached.([]*User); ok {
			return users, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/users", map[string]string{})
	if err != nil {
		return nil, err
	}
	
	// Parse response - handle both array format and object format
	var users []*User
	if err := json.Unmarshal(body, &users); err != nil {
		// Try object format
		var response struct {
			Users []*User `json:"users"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse users response: %v", err)
		}
		users = response.Users
	}
	
	// Cache result
	hp.setCache(cacheKey, users, 0)
	
	return users, nil
}

func (hp *HTTPProvider) ListGroups() ([]*Group, error) {
	cacheKey := "list_groups"
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if groups, ok := cached.([]*Group); ok {
			return groups, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/groups", map[string]string{})
	if err != nil {
		return nil, err
	}
	
	// Parse response - handle both array format and object format
	var groups []*Group
	if err := json.Unmarshal(body, &groups); err != nil {
		// Try object format
		var response struct {
			Groups []*Group `json:"groups"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse groups response: %v", err)
		}
		groups = response.Groups
	}
	
	// Add reserved warp-portal groups to the list
	reservedGroups := []*Group{
		{
			Name:    config.WarpPortalAdminGroup,
			GID:     config.WarpPortalAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		},
		{
			Name:    config.WarpPortalUserGroup,
			GID:     config.WarpPortalUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		},
	}
	
	// Prepend reserved groups to the list
	groups = append(reservedGroups, groups...)
	
	// Cache result
	hp.setCache(cacheKey, groups, 0)
	
	return groups, nil
}

func (hp *HTTPProvider) CheckSudo(username string) (bool, error) {
	cacheKey := fmt.Sprintf("sudo:%s", username)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if result, ok := cached.(bool); ok {
			return result, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/checksudo", map[string]string{"username": username})
	if err != nil {
		return false, err
	}
	
	// Parse response - handle both boolean and object format
	var result bool
	if err := json.Unmarshal(body, &result); err != nil {
		// Try object format
		var response struct {
			HasSudo bool `json:"has_sudo"`
			Allowed bool `json:"allowed"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return false, fmt.Errorf("failed to parse sudo response: %v", err)
		}
		result = response.HasSudo || response.Allowed
	}
	
	// Cache result with shorter TTL for security-sensitive data
	hp.setCache(cacheKey, result, hp.defaultTTL/2)
	
	return result, nil
}

func (hp *HTTPProvider) InitGroups(username string) ([]int, error) {
	cacheKey := fmt.Sprintf("initgroups:%s", username)
	
	// Check cache first
	if cached, found := hp.getCached(cacheKey); found {
		if groups, ok := cached.([]int); ok {
			return groups, nil
		}
	}
	
	// Make HTTP request
	body, err := hp.makeRequest("/initgroups", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}
	
	// Parse response - handle both array format and object format
	var groups []int
	if err := json.Unmarshal(body, &groups); err != nil {
		// Try object format
		var response struct {
			Groups []int `json:"groups"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse initgroups response: %v", err)
		}
		groups = response.Groups
	}
	
	// Add reserved warp-portal groups
	// Add warp-portal-user group for all authenticated users
	groups = append(groups, config.WarpPortalUserGID)
	
	// Check if user has admin privileges by calling CheckSudo
	if hasAdmin, err := hp.CheckSudo(username); err == nil && hasAdmin {
		groups = append(groups, config.WarpPortalAdminGID)
	}
	
	// Cache result
	hp.setCache(cacheKey, groups, 0)
	
	return groups, nil
}

func (hp *HTTPProvider) Reload() error {
	// Clear cache on reload
	hp.cacheMu.Lock()
	defer hp.cacheMu.Unlock()
	
	hp.cache = make(map[string]*cacheEntry)
	httpLog.Info("HTTP provider cache cleared")
	
	// Regenerate fingerprint
	var err error
	hp.fingerprint, err = getMachineFingerprint()
	if err != nil {
		httpLog.Error("Failed to regenerate machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}
	
	return nil
}