package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const DefaultSocketPath = "/run/p0_agent.sock"

// SocketClient provides communication with the P0 Agent daemon via Unix socket
type SocketClient struct {
	socketPath string
	timeout    time.Duration
}

// NewSocketClient creates a new socket client
func NewSocketClient() *SocketClient {
	return &SocketClient{
		socketPath: DefaultSocketPath,
		timeout:    5 * time.Second,
	}
}

// SetTimeout sets the connection timeout
func (c *SocketClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// RegistrationResponse represents a registration status response from the daemon
type RegistrationResponse struct {
	Status            string `json:"status"`
	Registered        bool   `json:"registered"`
	AgentID           string `json:"agent_id,omitempty"`
	EnvironmentID     string `json:"environment_id,omitempty"`
	BackendURL        string `json:"backend_url,omitempty"`
	LastCheck         string `json:"last_check,omitempty"`
	Error             string `json:"error,omitempty"`
	RegistrationError string `json:"registration_error,omitempty"`
}

// GetRegistrationStatus queries the daemon for registration status
func (c *SocketClient) GetRegistrationStatus() (*RegistrationResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon socket: %w", err)
	}
	defer conn.Close()

	// Send checklive request
	request := map[string]interface{}{
		"op": "checklive",
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read JSON response
	var response RegistrationResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}
