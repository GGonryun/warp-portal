package config

// Reserved Group IDs for p0-agent groups
// These GIDs are reserved and should not conflict with system groups
const (
	P0AgentAdminGID = 64200 // p0-agent-admin group
	P0AgentUserGID  = 64201 // p0-agent-user group
)

// Reserved group names
const (
	P0AgentAdminGroup = "p0-agent-admin"
	P0AgentUserGroup  = "p0-agent-user"
)