package config

// File paths used throughout the p0-agent daemon
const (
	// Socket path for daemon communication
	SocketPath = "/run/p0_agent.sock"
	
	// Configuration file path
	ConfigPath = "/etc/p0_agent/config.yaml"
	
	// Log file path
	LogPath = "/var/log/p0_agent_daemon.log"
)