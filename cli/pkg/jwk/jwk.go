package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v3"
)

const (
	DefaultConfigDir = "/etc/p0_agent"

	PrivateKeyFilename = "jwk_private_key.json"

	PublicKeyFilename = "jwk_public_key.json"
)

type KeyPair struct {
	PrivateKey jose.JSONWebKey `json:"private_key"`
	PublicKey  jose.JSONWebKey `json:"public_key"`
	KeyID      string          `json:"key_id"`
}

func Generate() (*KeyPair, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	keyID := fmt.Sprintf("%s-%d", hostname, time.Now().Unix())

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

	return &KeyPair{
		PrivateKey: privateJWK,
		PublicKey:  publicJWK,
		KeyID:      keyID,
	}, nil
}

func (kp *KeyPair) Save(configDir string) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	privateKeyPath := filepath.Join(configDir, PrivateKeyFilename)
	privateKeyData, err := json.MarshalIndent(kp.PrivateKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := os.WriteFile(privateKeyPath, privateKeyData, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	publicKeyPath := filepath.Join(configDir, PublicKeyFilename)
	publicKeyData, err := json.MarshalIndent(kp.PublicKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	if err := os.WriteFile(publicKeyPath, publicKeyData, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

func ReadPublicKey(configDir string) (string, error) {
	publicKeyPath := filepath.Join(configDir, PublicKeyFilename)

	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read JWK public key from %s: %w", publicKeyPath, err)
	}

	return string(data), nil
}

func ReadPublicKeyFromDefault() (string, error) {
	return ReadPublicKey(DefaultConfigDir)
}

func (kp *KeyPair) SaveToDefault() error {
	return kp.Save(DefaultConfigDir)
}
