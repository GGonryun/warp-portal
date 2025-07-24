package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SocketPath = "/run/warp_portal.sock"
	LogPath    = "/var/log/warp_portal_daemon.log"
	ConfigPath = "/etc/warp_portal/config.yaml"
)

type Request struct {
	Op             string `json:"op"`
	Username       string `json:"username,omitempty"`
	Groupname      string `json:"groupname,omitempty"`
	UID            int    `json:"uid,omitempty"`
	GID            int    `json:"gid,omitempty"`
	Index          int    `json:"index,omitempty"`
	KeyType        string `json:"key_type,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	// Session management fields
	RHost     string `json:"rhost,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

type UserResponse struct {
	Status string `json:"status"`
	User   *User  `json:"user,omitempty"`
	Error  string `json:"error,omitempty"`
}

type GroupResponse struct {
	Status string `json:"status"`
	Group  *Group `json:"group,omitempty"`
	Error  string `json:"error,omitempty"`
}

type KeyResponse struct {
	Status string   `json:"status"`
	Keys   []string `json:"keys,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type InitGroupsResponse struct {
	Status string `json:"status"`
	Groups []int  `json:"groups,omitempty"`
	Error  string `json:"error,omitempty"`
}

type SessionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Gecos string `json:"gecos"`
	Dir   string `json:"dir"`
	Shell string `json:"shell"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

// Plugin interface for data providers
type DataProvider interface {
	GetUser(username string) (*User, error)
	GetUserByUID(uid int) (*User, error)
	GetGroup(groupname string) (*Group, error)
	GetGroupByGID(gid int) (*Group, error)
	GetKeys(username string) ([]string, error)
	ListUsers() ([]*User, error)
	ListGroups() ([]*Group, error)
	CheckSudo(username string) (bool, error)
	InitGroups(username string) ([]int, error)
	Reload() error
}

// Log levels
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

var logLevelNames = map[string]LogLevel{
	"error": LogLevelError,
	"warn":  LogLevelWarn,
	"info":  LogLevelInfo,
	"debug": LogLevelDebug,
	"trace": LogLevelTrace,
}

var currentLogLevel LogLevel = LogLevelInfo

// Logging helper functions
func logError(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelError {
		log.Printf("[ERROR] "+format, args...)
	}
}

func logWarn(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelWarn {
		log.Printf("[WARN] "+format, args...)
	}
}

func logInfo(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func logDebug(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func logTrace(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelTrace {
		log.Printf("[TRACE] "+format, args...)
	}
}

// Main configuration structure
type Config struct {
	Provider   ProviderConfig         `yaml:"provider"`
	Users      map[string]ConfigUser  `yaml:"users,omitempty"`
	Groups     map[string]ConfigGroup `yaml:"groups,omitempty"`
	Sudoers    []string               `yaml:"sudoers,omitempty"`
	DenyUsers  []string               `yaml:"deny_users,omitempty"`
	DenyGroups []string               `yaml:"deny_groups,omitempty"`
	LogLevel   string                 `yaml:"log_level,omitempty"`
}

type ProviderConfig struct {
	Type   string                 `yaml:"type"` // "file", "http", etc.
	Config map[string]interface{} `yaml:"config,omitempty"`
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

// File-based data provider implementation
type FileProvider struct {
	config      *Config
	configMu    sync.RWMutex
	lastModTime time.Time
}

func NewFileProvider() *FileProvider {
	return &FileProvider{}
}

var (
	dataProvider DataProvider
	providerMu   sync.RWMutex
)

func (fp *FileProvider) Reload() error {
	fp.configMu.Lock()
	defer fp.configMu.Unlock()

	// Check if file exists
	if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
		logWarn("Config file not found at %s, using empty configuration", ConfigPath)
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
	fileInfo, err := os.Stat(ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(fp.lastModTime) {
		return nil // File hasn't changed
	}

	data, err := os.ReadFile(ConfigPath)
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

	// Update log level
	if config.LogLevel != "" {
		if level, exists := logLevelNames[strings.ToLower(config.LogLevel)]; exists {
			currentLogLevel = level
			logInfo("Log level set to: %s", config.LogLevel)
		} else {
			logWarn("Invalid log level '%s', using default 'info'", config.LogLevel)
		}
	}

	logInfo("Loaded configuration from %s", ConfigPath)

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

	// Find all groups where this user is a member (including primary group for now)
	// We'll let the NSS layer decide which ones to include
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
						logDebug("Added warp-portal-admin group (GID %d) for sudoer user %s", adminGid, username)
					}
				} else {
					logError("Warning: Failed to parse GID for warp-portal-admin group: %v", err)
				}
			} else {
				logError("Warning: warp-portal-admin group not found in system: %v", err)
			}
			break
		}
	}

	return groups, nil
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
			logDebug("Generated machine fingerprint from %s: %s", path, fingerprint)
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
	logDebug("Generated fallback machine fingerprint: %s", fingerprint)
	return fingerprint, nil
}

// Cache entry for HTTP provider
type cacheEntry struct {
	data      interface{}
	timestamp time.Time
	ttl       time.Duration
}

func (ce *cacheEntry) isExpired() bool {
	return time.Since(ce.timestamp) > ce.ttl
}

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
		logError("Failed to get machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}
	
	logInfo("HTTP provider initialized with URL: %s, TTL: %v, Timeout: %v", hp.baseURL, hp.defaultTTL, timeout)
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
	
	logDebug("Making HTTP request to %s with payload: %s", url, string(jsonData))
	
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
	
	logDebug("HTTP request successful, response: %s", string(body))
	return body, nil
}

func (hp *HTTPProvider) getCached(key string) (interface{}, bool) {
	hp.cacheMu.RLock()
	defer hp.cacheMu.RUnlock()
	
	if entry, exists := hp.cache[key]; exists && !entry.isExpired() {
		logDebug("Cache hit for key: %s", key)
		return entry.data, true
	}
	
	logDebug("Cache miss for key: %s", key)
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
	
	logDebug("Cached data for key: %s (TTL: %v)", key, ttl)
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
	
	// Parse response
	var response struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse keys response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, response.Keys, 0)
	
	return response.Keys, nil
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
	
	// Parse response
	var response struct {
		Users []*User `json:"users"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse users response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, response.Users, 0)
	
	return response.Users, nil
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
	
	// Parse response
	var response struct {
		Groups []*Group `json:"groups"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse groups response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, response.Groups, 0)
	
	return response.Groups, nil
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
	
	// Parse response
	var response struct {
		HasSudo bool `json:"has_sudo"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("failed to parse sudo response: %v", err)
	}
	
	// Cache result with shorter TTL for security-sensitive data
	hp.setCache(cacheKey, response.HasSudo, hp.defaultTTL/2)
	
	return response.HasSudo, nil
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
	
	// Parse response
	var response struct {
		Groups []int `json:"groups"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse initgroups response: %v", err)
	}
	
	// Cache result
	hp.setCache(cacheKey, response.Groups, 0)
	
	return response.Groups, nil
}

func (hp *HTTPProvider) Reload() error {
	// Clear cache on reload
	hp.cacheMu.Lock()
	defer hp.cacheMu.Unlock()
	
	hp.cache = make(map[string]*cacheEntry)
	logInfo("HTTP provider cache cleared")
	
	// Regenerate fingerprint
	var err error
	hp.fingerprint, err = getMachineFingerprint()
	if err != nil {
		logError("Failed to regenerate machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}
	
	return nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		logError("Error decoding request: %v", err)
		return
	}

	logTrace("Received request: %+v", req)

	switch req.Op {
	case "getpwnam":
		handleGetPwnam(encoder, req.Username)
	case "getpwuid":
		handleGetPwuid(encoder, req.UID)
	case "getgrnam":
		handleGetGrnam(encoder, req.Groupname)
	case "getgrgid":
		handleGetGrgid(encoder, req.GID)
	case "getpwent":
		handleGetPwent(encoder, req.Index)
	case "getgrent":
		handleGetGrent(encoder, req.Index)
	case "getkeys":
		handleGetKeys(encoder, req.Username, req.KeyType, req.KeyFingerprint)
	case "checksudo":
		handleCheckSudo(conn, req.Username)
	case "initgroups":
		handleInitGroups(encoder, req.Username)
	case "open_session":
		handleOpenSession(encoder, req.Username, req.RHost, req.Timestamp)
	case "close_session":
		handleCloseSession(encoder, req.Username, req.RHost, req.Timestamp)
	default:
		logWarn("Unknown operation: %s", req.Op)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  fmt.Sprintf("Unknown operation: %s", req.Op),
		})
	}
}

func handleGetPwnam(encoder *json.Encoder, username string) {
	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := provider.GetUser(username)
	if err != nil {
		logDebug("User not found: %s - %v", username, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	logInfo("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetPwuid(encoder *json.Encoder, uid int) {
	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := provider.GetUserByUID(uid)
	if err != nil {
		logDebug("User not found for UID: %d - %v", uid, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	logInfo("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetGrnam(encoder *json.Encoder, groupname string) {
	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := provider.GetGroup(groupname)
	if err != nil {
		logDebug("Group not found: %s - %v", groupname, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	logInfo("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetGrgid(encoder *json.Encoder, gid int) {
	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := provider.GetGroupByGID(gid)
	if err != nil {
		logDebug("Group not found for GID: %d - %v", gid, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	logInfo("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetPwent(encoder *json.Encoder, index int) {
	logTrace("getpwent requested for index: %d", index)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	users, err := provider.ListUsers()
	if err != nil {
		logError("Failed to list users: %v", err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Failed to list users",
		})
		return
	}

	if index < 0 || index >= len(users) {
		logWarn("Index out of range: %d (max: %d)", index, len(users)-1)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "End of enumeration",
		})
		return
	}

	user := users[index]
	logInfo("Found user at index %d: %s (UID: %d)", index, user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetGrent(encoder *json.Encoder, index int) {
	logTrace("getgrent requested for index: %d", index)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	groups, err := provider.ListGroups()
	if err != nil {
		logError("Failed to list groups: %v", err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Failed to list groups",
		})
		return
	}

	if index < 0 || index >= len(groups) {
		logWarn("Index out of range: %d (max: %d)", index, len(groups)-1)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "End of enumeration",
		})
		return
	}

	group := groups[index]
	logInfo("Found group at index %d: %s (GID: %d)", index, group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetKeys(encoder *json.Encoder, username, keyType, keyFingerprint string) {
	logTrace("Getting SSH keys for user: %s, type: %s, fingerprint: %s", username, keyType, keyFingerprint)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	// Reload configuration if needed
	if err := provider.Reload(); err != nil {
		logError("Failed to reload provider configuration: %v", err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Failed to load configuration",
		})
		return
	}

	keys, err := provider.GetKeys(username)
	if err != nil {
		logDebug("No SSH keys found for user: %s - %v", username, err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "No SSH keys found for user",
		})
		return
	}

	logInfo("Found %d SSH keys for user: %s", len(keys), username)
	encoder.Encode(KeyResponse{
		Status: "success",
		Keys:   keys,
	})
}

func handleCheckSudo(conn net.Conn, username string) {
	logTrace("Checking sudo access for user: %s", username)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		conn.Write([]byte("DENY\n"))
		return
	}

	// Reload configuration if needed
	if err := provider.Reload(); err != nil {
		logError("Failed to reload provider configuration: %v", err)
		conn.Write([]byte("DENY\n"))
		return
	}

	allowed, err := provider.CheckSudo(username)
	if err != nil {
		logError("Error checking sudo access for user %s: %v", username, err)
		conn.Write([]byte("DENY\n"))
		return
	}

	if allowed {
		logInfo("Sudo access granted for user: %s", username)
		conn.Write([]byte("ALLOW\n"))
	} else {
		logDebug("Sudo access denied for user: %s", username)
		conn.Write([]byte("DENY\n"))
	}
}

func handleInitGroups(encoder *json.Encoder, username string) {
	logTrace("Getting initgroups for user: %s", username)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		logError("Data provider not initialized")
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	groups, err := provider.InitGroups(username)
	if err != nil {
		if err.Error() == "user not found" {
			logDebug("User not found for initgroups: %s - %v", username, err)
			encoder.Encode(InitGroupsResponse{
				Status: "error",
				Error:  "User not found or groups unavailable",
			})
		} else {
			logError("Failed to get groups for user %s: %v", username, err)
			encoder.Encode(InitGroupsResponse{
				Status: "error",
				Error:  "User not found or groups unavailable",
			})
		}
		return
	}

	logInfo("Found %d groups for user %s: %v", len(groups), username, groups)
	encoder.Encode(InitGroupsResponse{
		Status: "success",
		Groups: groups,
	})
}

func handleOpenSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	logTrace("Handling session open: user=%s, rhost=%s, timestamp=%d",
		username, rhost, timestamp)

	// Validate required fields
	if username == "" {
		logWarn("Session open request missing username")
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "Missing username field",
		})
		return
	}

	logInfo("SESSION_OPEN: User %s opened session from %s at timestamp %d",
		username, rhost, timestamp)

	// Send success response
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session opened for user %s", username),
	})
}

func handleCloseSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	logTrace("Handling session close: user=%s, rhost=%s, timestamp=%d",
		username, rhost, timestamp)

	// Validate required fields
	if username == "" {
		logWarn("Session close request missing username")
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "Missing username field",
		})
		return
	}

	logInfo("SESSION_CLOSE: User %s closed session from %s at timestamp %d",
		username, rhost, timestamp)

	// Send success response
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session closed for user %s", username),
	})
}

func setupLogging() {
	logFile, err := os.OpenFile(LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logError("Failed to open log file %s, using stdout: %v", LogPath, err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logInfo("Logging to file: %s", LogPath)
}


func initializeProvider() error {
	// First, try to read configuration to determine provider type
	tempProvider := NewFileProvider()
	if err := tempProvider.Reload(); err != nil {
		// If config doesn't exist, use file provider with defaults
		logWarn("No configuration found, using file provider with defaults")
		providerMu.Lock()
		dataProvider = tempProvider
		providerMu.Unlock()
		return nil
	}

	// Read provider configuration
	tempProvider.configMu.RLock()
	providerType := "file" // default
	if tempProvider.config != nil && tempProvider.config.Provider.Type != "" {
		providerType = tempProvider.config.Provider.Type
	}
	tempProvider.configMu.RUnlock()

	switch providerType {
	case "file":
		providerMu.Lock()
		dataProvider = tempProvider
		providerMu.Unlock()
		logTrace("Data provider initialized: file")

	case "http":
		// Initialize HTTP provider
		tempProvider.configMu.RLock()
		config := tempProvider.config.Provider.Config
		tempProvider.configMu.RUnlock()
		
		httpProvider, err := NewHTTPProvider(config)
		if err != nil {
			return fmt.Errorf("failed to initialize HTTP provider: %v", err)
		}
		
		providerMu.Lock()
		dataProvider = httpProvider
		providerMu.Unlock()
		logTrace("Data provider initialized: http")

	default:
		return fmt.Errorf("unknown provider type: %s", providerType)
	}

	return nil
}

func main() {
	setupLogging()

	// Initialize data provider
	if err := initializeProvider(); err != nil {
		log.Fatalf("Failed to initialize data provider: %v", err)
	}

	// Remove existing socket if it exists
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	// Create Unix domain socket
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer listener.Close()

	// Set socket permissions
	if err := os.Chmod(SocketPath, 0666); err != nil {
		log.Fatalf("Failed to set socket permissions: %v", err)
	}

	logTrace("Warp portal daemon listening on %s", SocketPath)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logInfo("Received shutdown signal, cleaning up...")
		listener.Close()
		os.Remove(SocketPath)
		os.Exit(0)
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logError("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}
