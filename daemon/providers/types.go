package providers

import "time"

// User represents a system user account
type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Gecos string `json:"gecos"`
	Dir   string `json:"dir"`
	Shell string `json:"shell"`
}

// Group represents a system group
type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

// RegistrationStatus represents the current registration status
type RegistrationStatus struct {
	Registered bool      `json:"registered"`
	LastCheck  time.Time `json:"last_check,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// DataProvider defines the interface for user/group data providers
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
	CheckRegistration() (*RegistrationStatus, error)
	Reload() error
}
