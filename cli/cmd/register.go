package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cli/config"
	"cli/pkg/jwk"
	"cli/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	registerShowDetails bool
	registerLabels      []string
)

type RegistrationInfo struct {
	Hostname      string
	PublicIP      string
	Fingerprint   string
	PublicKey     string
	JWKPublicKey  string
	Code          string
	EnvironmentID string
	Labels        []string
}

type DaemonConfig struct {
	Version  string `yaml:"version"`
	Provider struct {
		Type        string                 `yaml:"type"`
		Environment string                 `yaml:"environment"`
		Config      map[string]interface{} `yaml:"config"`
	} `yaml:"provider"`
	Environment string   `yaml:"environment"`
	Labels      []string `yaml:"labels"`
}

type RegistrationRequest struct {
	Hostname      string   `json:"hostname"`
	PublicIP      string   `json:"public_ip"`
	Fingerprint   string   `json:"fingerprint"`
	PublicKey     string   `json:"public_key"`
	JWKPublicKey  string   `json:"jwk_public_key"`
	EnvironmentID string   `json:"environment_id"`
	Labels        []string `json:"labels,omitempty"`
	Timestamp     int64    `json:"timestamp"`
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register machine with P0 Agent (requires sudo)",
	Long: `Register this machine with P0 Agent.

This command will:
1. Collect system information (hostname, public IP, machine fingerprint)
2. Read the JWK public key from the installation
3. Generate a base64-encoded JSON registration code
4. Save registration status to /var/lib/p0_agent/registration.json

Environment ID is read from the daemon configuration file and is required for registration.

IMPORTANT: This command requires sudo privileges to write the registration status file.

The generated registration code should be used for manual registration at ` + config.RegistrationWebsite + `.`,
	RunE: runRegister,
}

func init() {
	rootCmd.AddCommand(registerCmd)

	registerCmd.Flags().BoolVar(&registerShowDetails, "details", false, "Show detailed system information")
	registerCmd.Flags().StringArrayVar(&registerLabels, "label", []string{}, "Machine label in key=value format (can be used multiple times, e.g., --label='region=us-west' --label='env=backend')")
}

func runRegister(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")
	dryRun := viper.GetBool("dry-run")

	// Check for sudo permissions (required for writing to /var/lib/p0_agent)
	if !dryRun && os.Geteuid() != 0 {
		return fmt.Errorf("registration requires sudo privileges to write status file. Please run: sudo %s register", os.Args[0])
	}

	// Determine environment ID with fallback hierarchy
	environmentID, err := getEnvironmentID(verbose, dryRun)
	if err != nil {
		return fmt.Errorf("failed to determine environment ID: %w", err)
	}

	if verbose {
		fmt.Println("🔗 Starting machine registration...")
		fmt.Printf("   Environment ID: %s\n", environmentID)
		fmt.Println()
	}

	if !dryRun {
		if err := checkDaemonInstallation(verbose); err != nil {
			return fmt.Errorf("daemon check failed: %w", err)
		}
	}

	regInfo, err := collectRegistrationInfo(environmentID, verbose, dryRun)
	if err != nil {
		return fmt.Errorf("failed to collect system information: %w", err)
	}

	if dryRun {
		fmt.Println("✅ Dry run completed successfully")
		return nil
	}

	registrationCode, err := generateBase64RegistrationCode(regInfo)
	if err != nil {
		return fmt.Errorf("failed to generate registration code: %w", err)
	}

	regInfo.Code = registrationCode

	if err := saveRegistrationStatus(regInfo); err != nil && verbose {
		fmt.Printf("⚠️  Warning: Could not save registration status: %v\n", err)
	}

	displayRegistrationInfo(regInfo, verbose)

	return nil
}

func checkDaemonInstallation(verbose bool) error {
	if verbose {
		fmt.Println("🔍 Checking daemon installation...")
	}

	if _, err := os.Stat("/usr/local/bin/p0_agent_daemon"); err != nil {
		return fmt.Errorf("daemon binary not found. Please run '%s install' first", config.CLIName)
	}

	if _, err := os.Stat("/etc/p0_agent/config.yaml"); err != nil {
		return fmt.Errorf("daemon configuration not found. Please run '%s install' first", config.CLIName)
	}

	if verbose {
		fmt.Println("✅ Daemon installation verified")
	}
	return nil
}

func getEnvironmentID(verbose, dryRun bool) (string, error) {
	// Check daemon config file (if not dry run)
	if !dryRun {
		if daemonConfig, err := loadDaemonConfig(); err == nil {
			if verbose {
				fmt.Printf("   Loaded daemon config - Provider type: %s\n", daemonConfig.Provider.Type)
				if daemonConfig.Version != "" {
					fmt.Printf("   Config version: %s\n", daemonConfig.Version)
				}
				fmt.Printf("   Provider environment field value: '%s'\n", daemonConfig.Provider.Environment)
				fmt.Printf("   Root environment field value: '%s'\n", daemonConfig.Environment)
			}
			// Check provider environment first, then root environment
			if daemonConfig.Provider.Environment != "" {
				if verbose {
					fmt.Printf("   Using environment ID from provider config: %s\n", daemonConfig.Provider.Environment)
				}
				return daemonConfig.Provider.Environment, nil
			} else if daemonConfig.Environment != "" {
				if verbose {
					fmt.Printf("   Using environment ID from root config: %s\n", daemonConfig.Environment)
				}
				return daemonConfig.Environment, nil
			} else {
				if verbose {
					fmt.Printf("   Environment field is empty or missing in both provider and root config\n")
				}
			}
		} else {
			return "", fmt.Errorf("failed to load daemon configuration: %w", err)
		}
	} else {
		// For dry run, return a mock environment
		return "example-environment", nil
	}

	// No environment configured - return error
	return "", fmt.Errorf("environment ID not configured in daemon config. Please set 'environment' field in provider configuration or at root level")
}

func collectRegistrationInfo(environmentID string, verbose, dryRun bool) (*RegistrationInfo, error) {
	if verbose {
		fmt.Println("📊 Collecting system information...")
	}

	regInfo := &RegistrationInfo{}

	if dryRun {
		fmt.Println("[DRY RUN] Would collect system information")
		regInfo.Hostname = "example-hostname"
		regInfo.PublicIP = "203.0.113.1"
		regInfo.Fingerprint = "SHA256:abc123def456"
		regInfo.PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockExamplePublicKeyData"
		regInfo.EnvironmentID = environmentID
		regInfo.Labels = validateLabels(registerLabels)
		regInfo.Code = "example-hostname,203.0.113.1,SHA256:abc123def456,ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockExamplePublicKeyData"
		return regInfo, nil
	}

	hostname, err := utils.GetHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	regInfo.Hostname = hostname

	if verbose {
		fmt.Printf("  Hostname: %s\n", hostname)
	}

	publicIP, err := utils.GetPublicIP()
	if err != nil {
		if verbose {
			fmt.Printf("  ⚠️  Warning: Could not determine public IP: %v\n", err)
			fmt.Printf("  Using 'unknown' as placeholder\n")
		}
		publicIP = "unknown"
	}
	regInfo.PublicIP = publicIP

	if verbose {
		fmt.Printf("  Public IP: %s\n", publicIP)
	}

	fingerprint, err := utils.GetMachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to generate machine fingerprint: %w", err)
	}
	regInfo.Fingerprint = fingerprint

	if verbose {
		fmt.Printf("  Machine Fingerprint: %s\n", fingerprint)
	}

	publicKey, err := utils.GetMachinePublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine public key: %w", err)
	}
	regInfo.PublicKey = publicKey

	if verbose {
		fmt.Printf("  Machine Public Key: %s\n", publicKey)
	}

	jwkPublicKey, err := jwk.ReadPublicKeyFromDefault()
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK public key: %w", err)
	}
	regInfo.JWKPublicKey = jwkPublicKey

	if verbose {
		fmt.Printf("  JWK Public Key: %s\n", jwkPublicKey)
	}

	// Set environment ID
	regInfo.EnvironmentID = environmentID
	if verbose {
		fmt.Printf("  Environment ID: %s\n", regInfo.EnvironmentID)
	}

	// Parse labels - use command line flag if provided, otherwise fall back to config
	if len(registerLabels) > 0 {
		regInfo.Labels = validateLabels(registerLabels)
		if verbose && len(regInfo.Labels) > 0 {
			fmt.Printf("  Labels (from --label flags): %v\n", regInfo.Labels)
		}
	} else {
		// Try to get labels from config file
		if daemonConfig, err := loadDaemonConfig(); err == nil && len(daemonConfig.Labels) > 0 {
			regInfo.Labels = daemonConfig.Labels
			if verbose {
				fmt.Printf("  Labels (from config): %v\n", regInfo.Labels)
			}
		}
	}

	if verbose {
		fmt.Println("✅ System information collected successfully")
	}

	return regInfo, nil
}

func generateBase64RegistrationCode(regInfo *RegistrationInfo) (string, error) {
	request := RegistrationRequest{
		Hostname:      regInfo.Hostname,
		PublicIP:      regInfo.PublicIP,
		Fingerprint:   regInfo.Fingerprint,
		PublicKey:     regInfo.PublicKey,
		JWKPublicKey:  regInfo.JWKPublicKey,
		EnvironmentID: regInfo.EnvironmentID,
		Labels:        regInfo.Labels,
		Timestamp:     time.Now().Unix(),
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return encoded, nil
}

func displayRegistrationInfo(regInfo *RegistrationInfo, verbose bool) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("🎫 Machine Registration Code Generated")
	fmt.Println("========================================")
	fmt.Println()

	fmt.Println("📋 Registration Code:")
	fmt.Printf("%s\n", regInfo.Code)
	fmt.Println()

	if registerShowDetails || verbose {
		fmt.Println("📊 System Information:")
		fmt.Printf("   Hostname:            %s\n", regInfo.Hostname)
		fmt.Printf("   Public IP:           %s\n", regInfo.PublicIP)
		fmt.Printf("   Machine Fingerprint: %s\n", regInfo.Fingerprint)
		fmt.Printf("   Machine Public Key:  %s\n", regInfo.PublicKey)
		fmt.Printf("   JWK Public Key:      %s\n", regInfo.JWKPublicKey)
		fmt.Printf("   Environment ID:      %s\n", regInfo.EnvironmentID)
		if len(regInfo.Labels) > 0 {
			fmt.Printf("   Labels:              %v\n", regInfo.Labels)
		}
		fmt.Println()
	}

	fmt.Println("🌐 Registration Instructions:")
	fmt.Println("   1. Copy the base64-encoded registration code above")
	fmt.Printf("   2. Go to: %s\n", config.RegistrationWebsite)
	fmt.Println("   3. Paste the registration code in the form")
	fmt.Println("   4. Follow the instructions to complete setup")
	fmt.Println("   5. Download your configuration file")
	fmt.Println("   6. Start the daemon: systemctl start p0_agent_daemon")
	fmt.Println()

	fmt.Println("📝 Next Steps:")
	fmt.Printf("   • Check status: %s status\n", config.CLIName)
	fmt.Println("   • View logs: journalctl -u p0_agent_daemon -f")
	fmt.Println("   • Get help: " + config.CLIName + " --help")
	fmt.Println()

	if regInfo.PublicIP == "unknown" {
		fmt.Println("⚠️  Note: Public IP could not be determined automatically.")
		fmt.Println("   You may need to manually specify your public IP during registration.")
		fmt.Println()
	}
}

func validateLabels(labels []string) []string {
	var result []string
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label != "" {
			result = append(result, label)
		}
	}
	return result
}

func loadDaemonConfig() (*DaemonConfig, error) {
	configPath := "/etc/p0_agent/config.yaml"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read daemon config from %s: %w", configPath, err)
	}

	var config DaemonConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse daemon config: %w", err)
	}

	// Validate config version if specified
	if config.Version != "" {
		if err := validateConfigVersion(config.Version); err != nil {
			return nil, fmt.Errorf("config validation failed: %w", err)
		}
	}

	return &config, nil
}

func validateConfigVersion(version string) error {
	supportedVersions := []string{"1.0"}

	for _, supported := range supportedVersions {
		if version == supported {
			return nil
		}
	}

	return fmt.Errorf("unsupported config version '%s', supported versions: %v", version, supportedVersions)
}

func saveRegistrationStatus(regInfo *RegistrationInfo) error {
	// Create registration status file in permanent directory
	statusDir := "/var/lib/p0_agent"
	statusFile := filepath.Join(statusDir, "registration.json")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(statusDir, 0755); err != nil {
		return fmt.Errorf("failed to create status directory: %w", err)
	}

	statusData := map[string]interface{}{
		"registered_at":  time.Now().Unix(),
		"hostname":       regInfo.Hostname,
		"public_ip":      regInfo.PublicIP,
		"fingerprint":    regInfo.Fingerprint,
		"environment_id": regInfo.EnvironmentID,
		"labels":         regInfo.Labels,
	}

	jsonData, err := json.MarshalIndent(statusData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registration status: %w", err)
	}

	if err := os.WriteFile(statusFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write registration status file: %w", err)
	}

	return nil
}
