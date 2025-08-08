package providers

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"p0_agent_daemon/logging"
)

var machineLogger = logging.NewLogger("machine")

// GetMachineFingerprint returns the SHA256 fingerprint of the machine's SSH host key
func GetMachineFingerprint() (string, error) {
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
				machineLogger.Debug("Generated machine fingerprint from %s: %s", path, fields[1])
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("no SSH host keys found or ssh-keygen failed")
}

// GetMachinePublicKey returns the SSH public key of the machine
func GetMachinePublicKey() (string, error) {
	hostKeyPaths := []string{
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}

	for _, path := range hostKeyPaths {
		if data, err := os.ReadFile(path); err == nil {
			// Return the public key content, trimmed of whitespace
			publicKey := strings.TrimSpace(string(data))
			machineLogger.Debug("Retrieved machine public key from %s", path)
			return publicKey, nil
		}
	}

	return "", fmt.Errorf("no SSH host public keys found")
}