package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
)

func GetHostname() (string, error) {
	return os.Hostname()
}

func GetPublicIP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
		"https://ifconfig.me",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if isValidIP(ip) {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("failed to determine public IP address")
}

func GetMachineFingerprint() (string, error) {
	fingerprint, err := getSSHHostKeyFingerprint()
	if err == nil {
		return fingerprint, nil
	}

	return "", fmt.Errorf("failed to get machine fingerprint: %w", err)
}

func getSSHHostKeyFingerprint() (string, error) {
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
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("no SSH host keys found or ssh-keygen failed")
}

func GetMachinePublicKey() (string, error) {
	hostKeyPaths := []string{
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}

	for _, path := range hostKeyPaths {
		if data, err := os.ReadFile(path); err == nil {
			// Return the public key content, trimmed of whitespace
			return strings.TrimSpace(string(data)), nil
		}
	}

	return "", fmt.Errorf("no SSH host public keys found")
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func GenerateRegistrationCode() (string, error) {
	hostname, err := GetHostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	publicIP, err := GetPublicIP()
	if err != nil {
		publicIP = "unknown"
	}

	fingerprint, err := GetMachineFingerprint()
	if err != nil {
		return "", fmt.Errorf("failed to generate machine fingerprint: %w", err)
	}

	publicKey, err := GetMachinePublicKey()
	if err != nil {
		return "", fmt.Errorf("failed to get machine public key: %w", err)
	}

	registrationCode := fmt.Sprintf("%s,%s,%s,%s", hostname, publicIP, fingerprint, publicKey)
	return registrationCode, nil
}

// JWKKeyPair represents a JWK key pair with both public and private keys
type JWKKeyPair struct {
	PrivateKey jose.JSONWebKey `json:"private_key"`
	PublicKey  jose.JSONWebKey `json:"public_key"`
	KeyID      string          `json:"key_id"`
}

// GenerateJWKKeyPair generates a new RSA JWK key pair using the jose library
func GenerateJWKKeyPair() (*JWKKeyPair, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate a unique key ID based on hostname and timestamp
	hostname, err := GetHostname()
	if err != nil {
		hostname = "unknown"
	}
	keyID := fmt.Sprintf("%s-%d", hostname, time.Now().Unix())

	// Create JWK from RSA key using jose library
	privateJWK := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	publicJWK := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	return &JWKKeyPair{
		PrivateKey: privateJWK,
		PublicKey:  publicJWK,
		KeyID:      keyID,
	}, nil
}

// SaveJWKKeyPair saves the JWK key pair to the specified directory
func SaveJWKKeyPair(keyPair *JWKKeyPair, configDir string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save private key
	privateKeyPath := filepath.Join(configDir, "jwk_private_key.json")
	privateKeyData, err := json.MarshalIndent(keyPair.PrivateKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	
	if err := os.WriteFile(privateKeyPath, privateKeyData, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	// Save public key
	publicKeyPath := filepath.Join(configDir, "jwk_public_key.json")
	publicKeyData, err := json.MarshalIndent(keyPair.PublicKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	
	if err := os.WriteFile(publicKeyPath, publicKeyData, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}
