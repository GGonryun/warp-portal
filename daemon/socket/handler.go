package socket

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"p0_agent_daemon/config"
	"p0_agent_daemon/logging"
	"p0_agent_daemon/providers"

	"gopkg.in/yaml.v3"
)

// Handler handles socket connections and requests
type Handler struct {
	provider     providers.DataProvider
	cacheManager *providers.CacheManager
	logger       *logging.Logger
	config       *providers.Config
	configMu     sync.RWMutex
	lastModTime  time.Time
}

func NewHandler(provider providers.DataProvider, cacheManager *providers.CacheManager) *Handler {
	h := &Handler{
		provider:     provider,
		cacheManager: cacheManager,
		logger:       logging.NewLogger("socket"),
	}

	if err := h.loadConfig(); err != nil {
		h.logger.Warn("Failed to load config for denial checking: %v", err)
	}

	return h
}

func (h *Handler) loadConfig() error {
	h.configMu.Lock()
	defer h.configMu.Unlock()

	if _, err := os.Stat(config.ConfigPath); os.IsNotExist(err) {
		h.logger.Debug("Config file not found at %s, denial checking disabled", config.ConfigPath)
		h.config = &providers.Config{
			DenyUsers:  []string{},
			DenyGroups: []string{},
			DenyUids:   []int{},
			DenyGids:   []int{},
			Cache: providers.CacheConfig{
				Enabled:         true,
				RefreshInterval: 24,
				OnDemandUpdate:  true,
			},
		}
		return nil
	}

	fileInfo, err := os.Stat(config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(h.lastModTime) {
		return nil // File hasn't changed
	}

	data, err := os.ReadFile(config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var cfg providers.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config YAML: %v", err)
	}

	h.config = &cfg
	h.lastModTime = fileInfo.ModTime()

	h.logger.Debug("Loaded config for denial checking from %s", config.ConfigPath)
	return nil
}

func (h *Handler) isUserDenied(username string) bool {
	h.configMu.RLock()
	defer h.configMu.RUnlock()

	if h.config == nil {
		return false
	}

	for _, deniedUser := range h.config.DenyUsers {
		if deniedUser == username {
			h.logger.Debug("User %s is in deny list, rejecting request", username)
			return true
		}
	}
	return false
}

func (h *Handler) isGroupDenied(groupname string) bool {
	h.configMu.RLock()
	defer h.configMu.RUnlock()

	if h.config == nil {
		return false
	}

	for _, deniedGroup := range h.config.DenyGroups {
		if deniedGroup == groupname {
			h.logger.Debug("Group %s is in deny list, rejecting request", groupname)
			return true
		}
	}
	return false
}

func (h *Handler) isUidDenied(uid int) bool {
	h.configMu.RLock()
	defer h.configMu.RUnlock()

	if h.config == nil {
		return false
	}

	for _, deniedUid := range h.config.DenyUids {
		if deniedUid == uid {
			h.logger.Debug("UID %d is in deny list, rejecting request", uid)
			return true
		}
	}
	return false
}

func (h *Handler) isGidDenied(gid int) bool {
	h.configMu.RLock()
	defer h.configMu.RUnlock()

	if h.config == nil {
		return false
	}

	for _, deniedGid := range h.config.DenyGids {
		if deniedGid == gid {
			h.logger.Debug("GID %d is in deny list, rejecting request", gid)
			return true
		}
	}
	return false
}

func (h *Handler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		h.logger.Error("Error decoding request: %v", err)
		return
	}

	h.logger.Trace("Received request: %+v", req)

	switch req.Op {
	case "getpwnam":
		h.handleGetPwnam(encoder, req.Username)
	case "getpwuid":
		h.handleGetPwuid(encoder, req.UID)
	case "getgrnam":
		h.handleGetGrnam(encoder, req.Groupname)
	case "getgrgid":
		h.handleGetGrgid(encoder, req.GID)
	case "getpwent":
		h.handleGetPwent(encoder, req.Index)
	case "getgrent":
		h.handleGetGrent(encoder, req.Index)
	case "getkeys":
		h.handleGetKeys(encoder, req.Username, req.KeyType, req.KeyFingerprint)
	case "checksudo":
		h.handleCheckSudo(conn, req.Username)
	case "sudo":
		h.handleCheckSudo(conn, req.Username)
	case "initgroups":
		h.handleInitGroups(encoder, req.Username)
	case "open_session":
		h.handleOpenSession(encoder, req.Username, req.RHost, req.Timestamp)
	case "close_session":
		h.handleCloseSession(encoder, req.Username, req.RHost, req.Timestamp)
	case "checklive":
		h.handleCheckLive(encoder)
	default:
		h.logger.Warn("Unknown operation: %s", req.Op)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  fmt.Sprintf("Unknown operation: %s", req.Op),
		})
	}
}
