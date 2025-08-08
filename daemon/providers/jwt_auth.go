package providers

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	DefaultJWKConfigDir       = "/etc/p0_agent"
	PrivateKeyFilename       = "jwk_private_key.json"
	DefaultTokenValidityDuration = 5 * time.Minute
)

// JWTTokenCache provides thread-safe caching of JWT tokens with automatic expiration
type JWTTokenCache struct {
	mu        sync.RWMutex
	token     string
	expiresAt time.Time
	privateKey *rsa.PrivateKey
	keyID     string
	validity  time.Duration
}

// JWTClaims represents the claims in our JWT token
type JWTClaims struct {
	jwt.Claims
	Fingerprint string `json:"fingerprint,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
}

// NewJWTTokenCache creates a new JWT token cache
func NewJWTTokenCache() (*JWTTokenCache, error) {
	return NewJWTTokenCacheWithConfig(DefaultJWKConfigDir, DefaultTokenValidityDuration)
}

// NewJWTTokenCacheWithConfig creates a new JWT token cache with custom configuration
func NewJWTTokenCacheWithConfig(configDir string, validity time.Duration) (*JWTTokenCache, error) {
	privateKey, keyID, err := loadPrivateKey(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &JWTTokenCache{
		privateKey: privateKey,
		keyID:     keyID,
		validity:  validity,
	}, nil
}

// GetToken returns a valid JWT token, creating a new one if expired or missing
func (c *JWTTokenCache) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we have a valid cached token
	if c.token != "" && time.Now().Before(c.expiresAt) {
		return c.token, nil
	}

	// Generate a new token
	token, expiresAt, err := c.generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	// Cache the new token
	c.token = token
	c.expiresAt = expiresAt

	return token, nil
}

// IsExpired checks if the current token is expired (thread-safe)
func (c *JWTTokenCache) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return c.token == "" || time.Now().After(c.expiresAt)
}

// generateToken creates a new JWT token with machine information
func (c *JWTTokenCache) generateToken() (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(c.validity)

	// Get machine information
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	fingerprint, err := GetMachineFingerprint()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get machine fingerprint: %w", err)
	}

	publicKey, err := GetMachinePublicKey()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get machine public key: %w", err)
	}

	ipAddress, _ := getPublicIPAddress()
	if ipAddress == "" {
		ipAddress = "unknown"
	}

	// Create claims
	claims := JWTClaims{
		Claims: jwt.Claims{
			Subject:   fingerprint,
			Issuer:    hostname,
			Audience:  jwt.Audience{"p0.app"},
			IssuedAt:  jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		Fingerprint: fingerprint,
		Hostname:    hostname,
		IPAddress:   ipAddress,
		PublicKey:   publicKey,
	}

	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       c.privateKey,
		},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", c.keyID),
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create JWT signer: %w", err)
	}

	// Sign the token
	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return token, expiresAt, nil
}

// loadPrivateKey loads the RSA private key from JWK file
func loadPrivateKey(configDir string) (*rsa.PrivateKey, string, error) {
	privateKeyPath := filepath.Join(configDir, PrivateKeyFilename)
	
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read private key file %s: %w", privateKeyPath, err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWK: %w", err)
	}

	privateKey, ok := jwk.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("JWK key is not an RSA private key")
	}

	return privateKey, jwk.KeyID, nil
}

// getPublicIPAddress attempts to get the machine's public IP address
func getPublicIPAddress() (string, error) {
	// Try to connect to a remote address to determine local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}