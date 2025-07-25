package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
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
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}

	for _, path := range hostKeyPaths {
		if data, err := os.ReadFile(path); err == nil {
			hash := sha256.Sum256(data)
			fingerprint := "SHA256:" + strings.TrimRight(hex.EncodeToString(hash[:]), "=")
			return fingerprint, nil
		}
	}

	return "", fmt.Errorf("no SSH host keys found at expected paths")
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

	registrationCode := fmt.Sprintf("%s,%s,%s", hostname, publicIP, fingerprint)
	return registrationCode, nil
}
