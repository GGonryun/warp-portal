package cmd

import (
	"fmt"
	"os"

	"portal/config"
	"portal/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	registerShowDetails bool
)

type RegistrationInfo struct {
	Hostname    string
	PublicIP    string
	Fingerprint string
	Code        string
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Generate machine registration code",
	Long: `Generate a registration code for this machine to register with Warp Portal.

This command will:
1. Collect system information (hostname, public IP, machine fingerprint)
2. Generate a unique registration code
3. Display instructions for completing registration

The registration code should be entered at ` + config.RegistrationWebsite + ` to complete
the registration process and download your configuration.`,
	RunE: runRegister,
}

func init() {
	rootCmd.AddCommand(registerCmd)

	registerCmd.Flags().BoolVar(&registerShowDetails, "details", false, "Show detailed system information")
}

func runRegister(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")
	dryRun := viper.GetBool("dry-run")

	if verbose {
		fmt.Println("🔗 Generating machine registration code...")
		fmt.Println()
	}

	if !dryRun {
		if err := checkDaemonInstallation(verbose); err != nil {
			return fmt.Errorf("daemon check failed: %w", err)
		}
	}

	regInfo, err := collectRegistrationInfo(verbose, dryRun)
	if err != nil {
		return fmt.Errorf("failed to collect system information: %w", err)
	}

	if dryRun {
		fmt.Println("✅ Dry run completed successfully")
		return nil
	}

	displayRegistrationInfo(regInfo, verbose)

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

func collectRegistrationInfo(verbose, dryRun bool) (*RegistrationInfo, error) {
	if verbose {
		fmt.Println("📊 Collecting system information...")
	}

	regInfo := &RegistrationInfo{}

	if dryRun {
		fmt.Println("[DRY RUN] Would collect system information")
		regInfo.Hostname = "example-hostname"
		regInfo.PublicIP = "203.0.113.1"
		regInfo.Fingerprint = "abc123def456"
		regInfo.Code = "example-hostname,203.0.113.1,abc123def456"
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
	fmt.Printf("   %s\n", regInfo.Code)
	fmt.Println()

	if registerShowDetails || verbose {
		fmt.Println("📊 System Information:")
		fmt.Printf("   Hostname:           %s\n", regInfo.Hostname)
		fmt.Printf("   Public IP:          %s\n", regInfo.PublicIP)
		fmt.Printf("   Machine Fingerprint: %s\n", regInfo.Fingerprint)
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
