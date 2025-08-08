package socket

import "p0_agent_daemon/providers"

// Request represents an incoming socket request
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

// UserResponse represents a user lookup response
type UserResponse struct {
	Status string          `json:"status"`
	User   *providers.User `json:"user,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// GroupResponse represents a group lookup response
type GroupResponse struct {
	Status string           `json:"status"`
	Group  *providers.Group `json:"group,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// KeyResponse represents an SSH key lookup response
type KeyResponse struct {
	Status string   `json:"status"`
	Keys   []string `json:"keys,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// InitGroupsResponse represents a group initialization response
type InitGroupsResponse struct {
	Status string `json:"status"`
	Groups []int  `json:"groups,omitempty"`
	Error  string `json:"error,omitempty"`
}

// SessionResponse represents a session management response
type SessionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// LiveResponse represents a registration status response
type LiveResponse struct {
	Status            string `json:"status"`
	Registered        bool   `json:"registered"`
	Error             string `json:"error,omitempty"`
	RegistrationError string `json:"registration_error,omitempty"`
}
