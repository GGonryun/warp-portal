package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"p0_agent_daemon/config"
	"p0_agent_daemon/logging"
)

var logger = logging.NewLogger("http-provider")

type HTTPProviderConfig struct {
	URL      string `yaml:"url" json:"url"`
	Timeout  int    `yaml:"timeout" json:"timeout"`
	CacheTTL int    `yaml:"cache_ttl" json:"cache_ttl"`
}

type HTTPProvider struct {
	config      *Config
	httpConfig  *HTTPProviderConfig
	client      *http.Client
	fingerprint string
	publicKey   string
}

func getMachineFingerprint() (string, error) {
	hostKeyPaths := []string{
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}

	for _, path := range hostKeyPaths {
		if _, err := os.Stat(path); err == nil {
			// Use ssh-keygen to generate SHA256 fingerprint
			cmd := exec.Command("ssh-keygen", "-l", "-f", path, "-E", "sha256")
			output, err := cmd.Output()
			if err != nil {
				continue // Try next key type
			}

			// Parse output: "2048 SHA256:abc123... user@host (RSA)"
			fields := strings.Fields(string(output))
			if len(fields) >= 2 && strings.HasPrefix(fields[1], "SHA256:") {
				logger.Debug("Generated machine fingerprint from %s: %s", path, fields[1])
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("no SSH host keys found or ssh-keygen failed")
}

func getMachinePublicKey() (string, error) {
	hostKeyPaths := []string{
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}

	for _, path := range hostKeyPaths {
		if data, err := os.ReadFile(path); err == nil {
			// Return the public key content, trimmed of whitespace
			publicKey := strings.TrimSpace(string(data))
			logger.Debug("Retrieved machine public key from %s", path)
			return publicKey, nil
		}
	}

	return "", fmt.Errorf("no SSH host public keys found")
}

func NewHTTPProvider(config *Config) (*HTTPProvider, error) {
	httpConfig := &HTTPProviderConfig{
		Timeout:  10,
		CacheTTL: 10,
	}

	if url, ok := config.Provider.Config["url"].(string); ok {
		httpConfig.URL = url
	} else {
		return nil, fmt.Errorf("http provider requires 'url' configuration")
	}

	if timeout, ok := config.Provider.Config["timeout"].(int); ok {
		httpConfig.Timeout = timeout
	}

	if cacheTTL, ok := config.Provider.Config["cache_ttl"].(int); ok {
		httpConfig.CacheTTL = cacheTTL
	}

	hp := &HTTPProvider{
		config:     config,
		httpConfig: httpConfig,
	}

	hp.client = &http.Client{
		Timeout: time.Duration(httpConfig.Timeout) * time.Second,
	}

	var err error
	hp.fingerprint, err = getMachineFingerprint()
	if err != nil {
		logger.Error("Failed to get machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}

	hp.publicKey, err = getMachinePublicKey()
	if err != nil {
		logger.Error("Failed to get machine public key: %v", err)
		hp.publicKey = "unknown"
	}

	logger.Info("HTTP provider initialized with URL: %s, Timeout: %ds", httpConfig.URL, httpConfig.Timeout)
	return hp, nil
}

func (hp *HTTPProvider) GetCacheTTL() time.Duration {
	return time.Duration(hp.httpConfig.CacheTTL) * time.Second
}

func (hp *HTTPProvider) makeRequest(endpoint string, params map[string]string) ([]byte, error) {
	url := hp.httpConfig.URL + endpoint

	// Get environment ID from config - check provider first, then root level
	environmentID := hp.config.Provider.Environment
	if environmentID == "" {
		environmentID = hp.config.Environment
	}
	if environmentID == "" {
		return nil, fmt.Errorf("environment ID not configured. Please set 'environment' field in provider configuration or at root level")
	}

	payload := map[string]interface{}{
		"fingerprint":    hp.fingerprint,
		"public_key":     hp.publicKey,
		"timestamp":      time.Now().Unix(),
		"environment_id": environmentID,
	}

	for k, v := range params {
		payload[k] = v
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	logger.Debug("Making HTTP request to %s with payload: %s", url, string(jsonData))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "p0-agent-daemon/1.0")

	resp, err := hp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request failed with status %d: %s", resp.StatusCode, string(body))
	}

	logger.Debug("HTTP request successful, response: %s", string(body))
	return body, nil
}

func (hp *HTTPProvider) GetUser(username string) (*User, error) {
	body, err := hp.makeRequest("/user", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %v", err)
	}

	return &user, nil
}

func (hp *HTTPProvider) GetUserByUID(uid int) (*User, error) {
	body, err := hp.makeRequest("/user", map[string]string{"uid": strconv.Itoa(uid)})
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %v", err)
	}

	return &user, nil
}

func (hp *HTTPProvider) GetGroup(groupname string) (*Group, error) {
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

	body, err := hp.makeRequest("/group", map[string]string{"groupname": groupname})
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group response: %v", err)
	}

	return &group, nil
}

func (hp *HTTPProvider) GetGroupByGID(gid int) (*Group, error) {
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

	body, err := hp.makeRequest("/group", map[string]string{"gid": strconv.Itoa(gid)})
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group response: %v", err)
	}

	return &group, nil
}

func (hp *HTTPProvider) GetKeys(username string) ([]string, error) {
	body, err := hp.makeRequest("/keys", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}

	var keys []string
	if err := json.Unmarshal(body, &keys); err != nil {
		var response struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse keys response: %v", err)
		}
		keys = response.Keys
	}

	return keys, nil
}

func (hp *HTTPProvider) ListUsers() ([]*User, error) {
	body, err := hp.makeRequest("/users", map[string]string{})
	if err != nil {
		return nil, err
	}

	var users []*User
	if err := json.Unmarshal(body, &users); err != nil {
		var response struct {
			Users []*User `json:"users"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse users response: %v", err)
		}
		users = response.Users
	}

	return users, nil
}

func (hp *HTTPProvider) ListGroups() ([]*Group, error) {
	body, err := hp.makeRequest("/groups", map[string]string{})
	if err != nil {
		return nil, err
	}

	var groups []*Group
	if err := json.Unmarshal(body, &groups); err != nil {
		var response struct {
			Groups []*Group `json:"groups"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse groups response: %v", err)
		}
		groups = response.Groups
	}

	reservedGroups := []*Group{
		{
			Name:    config.P0AgentAdminGroup,
			GID:     config.P0AgentAdminGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		},
		{
			Name:    config.P0AgentUserGroup,
			GID:     config.P0AgentUserGID,
			Members: []string{}, // Members are determined dynamically via InitGroups
		},
	}

	groups = append(reservedGroups, groups...)

	return groups, nil
}

func (hp *HTTPProvider) CheckSudo(username string) (bool, error) {
	body, err := hp.makeRequest("/sudo", map[string]string{"username": username})
	if err != nil {
		return false, err
	}

	var result bool
	if err := json.Unmarshal(body, &result); err != nil {
		var response struct {
			HasSudo bool `json:"has_sudo"`
			Allowed bool `json:"allowed"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return false, fmt.Errorf("failed to parse sudo response: %v", err)
		}
		result = response.HasSudo || response.Allowed
	}

	return result, nil
}

func (hp *HTTPProvider) InitGroups(username string) ([]int, error) {
	body, err := hp.makeRequest("/initgroups", map[string]string{"username": username})
	if err != nil {
		return nil, err
	}

	var groups []int
	if err := json.Unmarshal(body, &groups); err != nil {
		var response struct {
			Groups []int `json:"groups"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse initgroups response: %v", err)
		}
		groups = response.Groups
	}

	groups = append(groups, config.P0AgentUserGID)

	if hasAdmin, err := hp.CheckSudo(username); err == nil && hasAdmin {
		groups = append(groups, config.P0AgentAdminGID)
	}

	return groups, nil
}

func (hp *HTTPProvider) Reload() error {
	var err error
	hp.fingerprint, err = getMachineFingerprint()
	if err != nil {
		logger.Error("Failed to regenerate machine fingerprint: %v", err)
		hp.fingerprint = "unknown"
	}

	hp.publicKey, err = getMachinePublicKey()
	if err != nil {
		logger.Error("Failed to regenerate machine public key: %v", err)
		hp.publicKey = "unknown"
	}

	return nil
}

func (hp *HTTPProvider) CheckRegistration() (*RegistrationStatus, error) {
	body, err := hp.makeRequest("/live", map[string]string{})
	if err != nil {
		return &RegistrationStatus{
			Registered: false,
			Error:      err.Error(),
		}, nil
	}

	var response struct {
		OK bool `json:"ok"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return &RegistrationStatus{
			Registered: false,
			Error:      fmt.Sprintf("failed to parse live response: %v", err),
		}, nil
	}

	// Get environment ID from config
	environmentID := hp.config.Provider.Environment
	if environmentID == "" {
		environmentID = hp.config.Environment
	}

	status := &RegistrationStatus{
		Registered: response.OK,
		LastCheck:  time.Now(),
	}

	if !response.OK {
		status.Error = "registration not active"
	}

	return status, nil
}
