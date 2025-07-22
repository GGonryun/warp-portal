package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
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

// Main configuration structure
type Config struct {
	Provider ProviderConfig         `yaml:"provider"`
	Users    map[string]ConfigUser  `yaml:"users,omitempty"`
	Groups   map[string]ConfigGroup `yaml:"groups,omitempty"`
	Sudoers  []string               `yaml:"sudoers,omitempty"`
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
		log.Printf("Config file not found at %s, using empty configuration", ConfigPath)
		fp.config = &Config{
			Provider: ProviderConfig{Type: "file"},
			Users:    map[string]ConfigUser{},
			Groups:   map[string]ConfigGroup{},
			Sudoers:  []string{},
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
	log.Printf("Loaded configuration from %s", ConfigPath)

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

	return groups, nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Error decoding request: %v", err)
		return
	}

	log.Printf("Received request: %+v", req)

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
		log.Printf("Unknown operation: %s", req.Op)
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
		log.Printf("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := provider.GetUser(username)
	if err != nil {
		log.Printf("User not found: %s - %v", username, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	log.Printf("Found user: %s (UID: %d)", user.Name, user.UID)
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
		log.Printf("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := provider.GetUserByUID(uid)
	if err != nil {
		log.Printf("User not found for UID: %d - %v", uid, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	log.Printf("Found user: %s (UID: %d)", user.Name, user.UID)
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
		log.Printf("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := provider.GetGroup(groupname)
	if err != nil {
		log.Printf("Group not found: %s - %v", groupname, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	log.Printf("Found group: %s (GID: %d)", group.Name, group.GID)
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
		log.Printf("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := provider.GetGroupByGID(gid)
	if err != nil {
		log.Printf("Group not found for GID: %d - %v", gid, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	log.Printf("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetPwent(encoder *json.Encoder, index int) {
	log.Printf("getpwent requested for index: %d", index)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		log.Printf("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	users, err := provider.ListUsers()
	if err != nil {
		log.Printf("Failed to list users: %v", err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Failed to list users",
		})
		return
	}

	if index < 0 || index >= len(users) {
		log.Printf("Index out of range: %d (max: %d)", index, len(users)-1)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "End of enumeration",
		})
		return
	}

	user := users[index]
	log.Printf("Found user at index %d: %s (UID: %d)", index, user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetGrent(encoder *json.Encoder, index int) {
	log.Printf("getgrent requested for index: %d", index)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		log.Printf("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	groups, err := provider.ListGroups()
	if err != nil {
		log.Printf("Failed to list groups: %v", err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Failed to list groups",
		})
		return
	}

	if index < 0 || index >= len(groups) {
		log.Printf("Index out of range: %d (max: %d)", index, len(groups)-1)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "End of enumeration",
		})
		return
	}

	group := groups[index]
	log.Printf("Found group at index %d: %s (GID: %d)", index, group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetKeys(encoder *json.Encoder, username, keyType, keyFingerprint string) {
	log.Printf("Getting SSH keys for user: %s, type: %s, fingerprint: %s", username, keyType, keyFingerprint)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		log.Printf("Data provider not initialized")
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	// Reload configuration if needed
	if err := provider.Reload(); err != nil {
		log.Printf("Failed to reload provider configuration: %v", err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Failed to load configuration",
		})
		return
	}

	keys, err := provider.GetKeys(username)
	if err != nil {
		log.Printf("No SSH keys found for user: %s - %v", username, err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "No SSH keys found for user",
		})
		return
	}

	log.Printf("Found %d SSH keys for user: %s", len(keys), username)
	encoder.Encode(KeyResponse{
		Status: "success",
		Keys:   keys,
	})
}

func handleCheckSudo(conn net.Conn, username string) {
	log.Printf("Checking sudo access for user: %s", username)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		log.Printf("Data provider not initialized")
		conn.Write([]byte("DENY\n"))
		return
	}

	// Reload configuration if needed
	if err := provider.Reload(); err != nil {
		log.Printf("Failed to reload provider configuration: %v", err)
		conn.Write([]byte("DENY\n"))
		return
	}

	allowed, err := provider.CheckSudo(username)
	if err != nil {
		log.Printf("Error checking sudo access for user %s: %v", username, err)
		conn.Write([]byte("DENY\n"))
		return
	}

	if allowed {
		log.Printf("Sudo access granted for user: %s", username)
		conn.Write([]byte("ALLOW\n"))
	} else {
		log.Printf("Sudo access denied for user: %s", username)
		conn.Write([]byte("DENY\n"))
	}
}

func handleInitGroups(encoder *json.Encoder, username string) {
	log.Printf("Getting initgroups for user: %s", username)

	providerMu.RLock()
	provider := dataProvider
	providerMu.RUnlock()

	if provider == nil {
		log.Printf("Data provider not initialized")
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	groups, err := provider.InitGroups(username)
	if err != nil {
		log.Printf("Failed to get groups for user %s: %v", username, err)
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "User not found or groups unavailable",
		})
		return
	}

	log.Printf("Found %d groups for user %s: %v", len(groups), username, groups)
	encoder.Encode(InitGroupsResponse{
		Status: "success",
		Groups: groups,
	})
}

func handleOpenSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	log.Printf("Handling session open: user=%s, rhost=%s, timestamp=%d",
		username, rhost, timestamp)

	// Validate required fields
	if username == "" {
		log.Printf("Session open request missing username")
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "Missing username field",
		})
		return
	}

	log.Printf("SESSION_OPEN: User %s opened session from %s at timestamp %d",
		username, rhost, timestamp)

	// Send success response
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session opened for user %s", username),
	})
}

func handleCloseSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	log.Printf("Handling session close: user=%s, rhost=%s, timestamp=%d",
		username, rhost, timestamp)

	// Validate required fields
	if username == "" {
		log.Printf("Session close request missing username")
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "Missing username field",
		})
		return
	}

	log.Printf("SESSION_CLOSE: User %s closed session from %s at timestamp %d",
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
		log.Printf("Warning: Failed to open log file %s, using stdout: %v", LogPath, err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Logging to file: %s", LogPath)
}

// HTTP Provider stub for future implementation
type HTTPProvider struct {
	config   *Config
	baseURL  string
	cacheTTL time.Duration
	timeout  time.Duration
	configMu sync.RWMutex
}

func NewHTTPProvider(baseURL string, cacheTTL, timeout time.Duration) *HTTPProvider {
	return &HTTPProvider{
		baseURL:  baseURL,
		cacheTTL: cacheTTL,
		timeout:  timeout,
	}
}

// Stub implementations for HTTPProvider
func (hp *HTTPProvider) GetUser(username string) (*User, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) GetUserByUID(uid int) (*User, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) GetGroup(groupname string) (*Group, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) GetGroupByGID(gid int) (*Group, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) GetKeys(username string) ([]string, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) ListUsers() ([]*User, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) ListGroups() ([]*Group, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) CheckSudo(username string) (bool, error) {
	return false, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) InitGroups(username string) ([]int, error) {
	return nil, fmt.Errorf("HTTP provider not yet implemented")
}

func (hp *HTTPProvider) Reload() error {
	return fmt.Errorf("HTTP provider not yet implemented")
}

func initializeProvider() error {
	// First, try to read configuration to determine provider type
	tempProvider := NewFileProvider()
	if err := tempProvider.Reload(); err != nil {
		// If config doesn't exist, use file provider with defaults
		log.Printf("No configuration found, using file provider with defaults")
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
		log.Printf("Data provider initialized: file")

	case "http":
		// Future HTTP provider initialization
		return fmt.Errorf("HTTP provider not yet implemented - use 'file' provider for now")

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

	log.Printf("Warp portal daemon listening on %s", SocketPath)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		listener.Close()
		os.Remove(SocketPath)
		os.Exit(0)
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}
