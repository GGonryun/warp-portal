package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"cli/config"
	"cli/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	registerShowDetails bool
	registerPrintCode   bool
	registerLabels      string
)

type RegistrationInfo struct {
	Hostname      string
	PublicIP      string
	Fingerprint   string
	PublicKey     string
	Code          string
	EnvironmentID string
	Labels        []string
}

type DaemonConfig struct {
	Provider struct {
		Type        string                 `yaml:"type"`
		Environment string                 `yaml:"environment"`
		Config      map[string]interface{} `yaml:"config"`
	} `yaml:"provider"`
}

type RegistrationRequest struct {
	Hostname      string   `json:"hostname"`
	PublicIP      string   `json:"public_ip"`
	Fingerprint   string   `json:"fingerprint"`
	PublicKey     string   `json:"public_key"`
	EnvironmentID string   `json:"environment_id"`
	Labels        []string `json:"labels,omitempty"`
	Key           string   `json:"key"`
	Timestamp     int64    `json:"timestamp"`
}

type RegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register machine with Warp Portal",
	Long: `Register this machine with Warp Portal.

This command will:
1. Collect system information (hostname, public IP, machine fingerprint)
2. Automatically register with the API endpoint (if configured)
3. Generate a local registration code (if --print-code is used)

Environment ID is read from the daemon configuration file. If not configured, defaults to "default".

If an API endpoint is configured in the daemon config, registration will be automatic.
Otherwise, use --print-code to generate a code for manual registration at ` + config.RegistrationWebsite + `.`,
	RunE: runRegister,
}

func init() {
	rootCmd.AddCommand(registerCmd)

	registerCmd.Flags().BoolVar(&registerShowDetails, "details", false, "Show detailed system information")
	registerCmd.Flags().BoolVar(&registerPrintCode, "print-code", false, "Print registration code for manual registration")
	registerCmd.Flags().StringVar(&registerLabels, "labels", "", "Semicolon-delimited list of machine labels (e.g., 'region=us-west;team=backend')")
}

func runRegister(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")
	dryRun := viper.GetBool("dry-run")

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

	// Try automatic registration if API endpoint is configured
	apiRegistered := false
	if !registerPrintCode {
		if err := attemptAPIRegistration(regInfo, verbose); err != nil {
			if verbose {
				fmt.Printf("⚠️  API registration failed: %v\n", err)
				fmt.Println("Falling back to manual registration code...")
				fmt.Println()
			}
		} else {
			apiRegistered = true
		}
	}

	// Display registration code if requested or if API registration failed
	if registerPrintCode || !apiRegistered {
		displayRegistrationInfo(regInfo, verbose)
	}

	return nil
}

func checkDaemonInstallation(verbose bool) error {
	if verbose {
		fmt.Println("🔍 Checking daemon installation...")
	}

	if _, err := os.Stat("/usr/local/bin/warp_portal_daemon"); err != nil {
		return fmt.Errorf("daemon binary not found. Please run '%s install' first", config.CLIName)
	}

	if _, err := os.Stat("/etc/warp_portal/config.yaml"); err != nil {
		return fmt.Errorf("daemon configuration not found. Please run '%s install' first", config.CLIName)
	}

	if verbose {
		fmt.Println("✅ Daemon installation verified")
	}
	return nil
}

func getEnvironmentID(verbose, dryRun bool) (string, error) {
	// Priority 1: Daemon config file (if not dry run)
	if !dryRun {
		if daemonConfig, err := loadDaemonConfig(); err == nil {
			if daemonConfig.Provider.Environment != "" {
				if verbose {
					fmt.Printf("   Using environment ID from config: %s\n", daemonConfig.Provider.Environment)
				}
				return daemonConfig.Provider.Environment, nil
			}
		} else if verbose {
			fmt.Printf("   Could not load daemon config: %v\n", err)
		}
	}

	// Priority 2: Default value
	defaultEnv := "default"
	if verbose {
		fmt.Printf("   Using default environment ID: %s\n", defaultEnv)
	}
	return defaultEnv, nil
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
		regInfo.Labels = parseLabels(registerLabels)
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

	// Set environment ID
	regInfo.EnvironmentID = environmentID
	if verbose {
		fmt.Printf("  Environment ID: %s\n", regInfo.EnvironmentID)
	}

	// Parse labels
	regInfo.Labels = parseLabels(registerLabels)
	if verbose && len(regInfo.Labels) > 0 {
		fmt.Printf("  Labels: %v\n", regInfo.Labels)
	}

	code, err := utils.GenerateRegistrationCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate registration code: %w", err)
	}
	regInfo.Code = code

	if verbose {
		fmt.Println("✅ System information collected successfully")
	}

	return regInfo, nil
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
		fmt.Printf("   Environment ID:      %s\n", regInfo.EnvironmentID)
		if len(regInfo.Labels) > 0 {
			fmt.Printf("   Labels:              %v\n", regInfo.Labels)
		}
		fmt.Println()
	}

	fmt.Println("🌐 Registration Instructions:")
	fmt.Println("   1. Copy the registration code above")
	fmt.Printf("   2. Go to: %s\n", config.RegistrationWebsite)
	fmt.Println("   3. Paste the registration code in the form")
	fmt.Println("   4. Follow the instructions to complete setup")
	fmt.Println("   5. Download your configuration file")
	fmt.Println("   6. Start the daemon: systemctl start warp_portal_daemon")
	fmt.Println()

	fmt.Println("📝 Next Steps:")
	fmt.Printf("   • Check status: %s status\n", config.CLIName)
	fmt.Println("   • View logs: journalctl -u warp_portal_daemon -f")
	fmt.Println("   • Get help: " + config.CLIName + " --help")
	fmt.Println()

	if regInfo.PublicIP == "unknown" {
		fmt.Println("⚠️  Note: Public IP could not be determined automatically.")
		fmt.Println("   You may need to manually specify your public IP during registration.")
		fmt.Println()
	}
}

func parseLabels(labelsStr string) []string {
	if labelsStr == "" {
		return nil
	}
	
	labels := strings.Split(labelsStr, ";")
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
	configPath := "/etc/warp_portal/config.yaml"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read daemon config: %w", err)
	}

	var config DaemonConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse daemon config: %w", err)
	}

	return &config, nil
}

func attemptAPIRegistration(regInfo *RegistrationInfo, verbose bool) error {
	daemonConfig, err := loadDaemonConfig()
	if err != nil {
		return fmt.Errorf("failed to load daemon config: %w", err)
	}

	if daemonConfig.Provider.Type != "http" {
		return fmt.Errorf("automatic registration requires HTTP provider")
	}

	baseURL, ok := daemonConfig.Provider.Config["url"].(string)
	if !ok || baseURL == "" {
		return fmt.Errorf("HTTP provider URL not configured")
	}

	// Construct registration endpoint
	registerURL := strings.TrimSuffix(baseURL, "/") + "/register"

	if verbose {
		fmt.Printf("🌐 Attempting automatic registration at: %s\n", registerURL)
	}

	request := RegistrationRequest{
		Hostname:      regInfo.Hostname,
		PublicIP:      regInfo.PublicIP,
		Fingerprint:   regInfo.Fingerprint,
		PublicKey:     regInfo.PublicKey,
		EnvironmentID: regInfo.EnvironmentID,
		Labels:        regInfo.Labels,
		Key:           regInfo.Code,
		Timestamp:     time.Now().Unix(),
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(registerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	var response RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("registration failed: %s", response.Message)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("✅ Automatic Registration Successful")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("📝 Registration Message: %s\n", response.Message)
	if response.Code != "" {
		fmt.Printf("🎫 Registration Code: %s\n", response.Code)
	}
	fmt.Println()
	fmt.Println("📝 Next Steps:")
	fmt.Printf("   • Check status: %s status\n", config.CLIName)
	fmt.Println("   • View logs: journalctl -u warp_portal_daemon -f")
	fmt.Println("   • Get help: " + config.CLIName + " --help")
	fmt.Println()

	return nil
}
