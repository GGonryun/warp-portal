package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"cli/config"
	"cli/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	installRepo     string
	installBranch   string
	installForce    bool
	installDepsOnly bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install P0 Agent system components",
	Long: `Install all P0 Agent components including:
- Daemon (Go binary and systemd service with cache management)
- NSS socket module (Name Service Switch integration)
- NSS cache module (Local file-based caching for performance)
- PAM module (Pluggable Authentication Module)
- SSH module (Authorized keys handler)
- Sudo configuration (Group-based access control)

This command will:
1. Install system dependencies (git, build-essential, gcc, pkg-config)
2. Clone the P0 Agent repository
3. Install component dependencies (Go, C libraries, etc.)
4. Build all components using make
5. Install system components with automatic backups
6. Generate JWK key pair for JWT authentication
7. Clean up temporary files
8. Verify installation

Use --deps-only to install only system and component dependencies without building or installing components.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Allow dry run without root privileges
		dryRun := viper.GetBool("dry-run")
		if !dryRun && os.Geteuid() != 0 {
			return fmt.Errorf("installation requires root privileges. Please run with sudo")
		}
		return nil
	},
	RunE: runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)

	installCmd.Flags().StringVar(&installRepo, "repo", config.DefaultRepository, "Git repository URL")
	installCmd.Flags().StringVar(&installBranch, "branch", config.DefaultBranch, "Git branch to clone")
	installCmd.Flags().BoolVar(&installForce, "force", false, "Force installation even if components already exist")
	installCmd.Flags().BoolVar(&installDepsOnly, "deps-only", false, "Install only system and component dependencies without building or installing components")
}

func runInstall(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")
	dryRun := viper.GetBool("dry-run")

	if verbose {
		if installDepsOnly {
			fmt.Println("🚀 Starting P0 Agent dependency installation...")
		} else {
			fmt.Println("🚀 Starting P0 Agent installation...")
		}
		fmt.Printf("Repository: %s\n", installRepo)
		fmt.Printf("Branch: %s\n", installBranch)
		fmt.Printf("Force: %t\n", installForce)
		fmt.Printf("Dependencies only: %t\n", installDepsOnly)
		fmt.Printf("Dry run: %t\n", dryRun)
		fmt.Println()
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "p0-agent-install-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil && verbose {
			fmt.Printf("⚠️  Warning: failed to clean up temporary directory %s: %v\n", tempDir, err)
		} else if verbose {
			fmt.Printf("🧹 Cleaned up temporary directory: %s\n", tempDir)
		}
	}()

	if verbose {
		fmt.Printf("📁 Created temporary directory: %s\n", tempDir)
	}

	if err := installSystemDependencies(verbose, dryRun); err != nil {
		return fmt.Errorf("failed to install system dependencies: %w", err)
	}

	if err := cloneRepository(tempDir, verbose, dryRun); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	repoDir := filepath.Join(tempDir, "p0-agent")

	if !installForce && !installDepsOnly {
		if err := checkExistingInstallation(verbose); err != nil {
			return err
		}
	}

	if err := installComponentDependencies(repoDir, verbose, dryRun); err != nil {
		return fmt.Errorf("failed to install component dependencies: %w", err)
	}

	if installDepsOnly {
		fmt.Println()
		fmt.Println("✅ P0 Agent dependencies installed successfully!")
		fmt.Println()
		fmt.Println("   Run 'p0 install' without --deps-only to complete the full installation.")
		return nil
	}

	if err := buildComponents(repoDir, verbose, dryRun); err != nil {
		return fmt.Errorf("failed to build components: %w", err)
	}

	if err := installComponents(repoDir, verbose, dryRun); err != nil {
		return fmt.Errorf("failed to install components: %w", err)
	}

	if err := generateJWKKeyPair(verbose, dryRun); err != nil {
		return fmt.Errorf("failed to generate JWK key pair: %w", err)
	}

	if err := verifyInstallation(verbose, dryRun); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	fmt.Println()
	fmt.Println("✅ P0 Agent installation completed successfully!")
	fmt.Println()
	fmt.Println("📋 Next steps:")
	fmt.Println("  1. Configure /etc/p0_agent/config.yaml")
	fmt.Println("  2. Run 'p0 register' to register with P0 backend")
	fmt.Println("  3. Start the daemon: systemctl start p0_agent_daemon")
	fmt.Println("  4. ⚠️  RESTART SSH service: sudo systemctl restart sshd")
	fmt.Println("     (Required for SSH authentication to work)")
	fmt.Println("  5. Check status: p0 status")

	return nil
}

func installSystemDependencies(verbose, dryRun bool) error {
	fmt.Println("📦 Installing system dependencies...")

	if dryRun {
		fmt.Println("[DRY RUN] Would install system dependencies")
		return nil
	}

	if _, err := os.Stat("/usr/bin/apt-get"); err != nil {
		fmt.Println("⚠️  Non-Debian system detected, skipping automatic dependency installation")
		if verbose {
			fmt.Println("   Please ensure you have: git, build-essential, gcc, pkg-config installed")
		}
		return nil
	}

	dependencies := []string{"git", "build-essential", "gcc", "pkg-config"}

	fmt.Print("  Updating package lists...")
	if !verbose {
		fmt.Print(" ")
	} else {
		fmt.Println()
	}

	updateCmd := exec.Command("sudo", "apt-get", "update")
	if verbose {
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
	} else {
		updateCmd.Stderr = os.Stderr
	}

	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	if !verbose {
		fmt.Println("✅")
	}

	fmt.Printf("  Installing dependencies: %v...", dependencies)
	if !verbose {
		fmt.Print(" ")
	} else {
		fmt.Println()
	}

	installArgs := []string{"apt-get", "install", "-y"}
	installArgs = append(installArgs, dependencies...)
	installCmd := exec.Command("sudo", installArgs...)

	if verbose {
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
	} else {
		installCmd.Stderr = os.Stderr
	}

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install system dependencies: %w", err)
	}

	if !verbose {
		fmt.Println("✅")
	} else {
		fmt.Println("✅ System dependencies installed successfully")
	}

	return nil
}

func cloneRepository(tempDir string, verbose, dryRun bool) error {
	fmt.Printf("📥 Cloning repository %s (branch: %s)...", installRepo, installBranch)
	if !verbose {
		fmt.Print(" ")
	} else {
		fmt.Println()
	}

	if dryRun {
		fmt.Printf("[DRY RUN] Would clone: git clone --branch %s --depth 1 %s\n", installBranch, installRepo)
		return nil
	}

	cmd := exec.Command("git", "clone", "--branch", installBranch, "--depth", "1", installRepo, "p0-agent")
	cmd.Dir = tempDir
	cmd.Stdout = os.Stdout
	if verbose {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	if !verbose {
		fmt.Println("✅")
	} else {
		fmt.Println("✅ Repository cloned successfully")
	}
	return nil
}

func checkExistingInstallation(verbose bool) error {
	if verbose {
		fmt.Println("🔍 Checking for existing installation...")
	}

	components := []struct {
		name string
		path string
	}{
		{"Daemon binary", "/usr/local/bin/p0_agent_daemon"},
		{"NSS socket module", "/usr/lib/x86_64-linux-gnu/libnss_socket.so.2"},
		{"NSS cache module", "/usr/lib/x86_64-linux-gnu/libnss_cache.so.2"},
		{"PAM module", "/lib/x86_64-linux-gnu/security/pam_sockauth.so"},
		{"SSH module", "/usr/local/bin/authorized_keys_socket"},
		{"Systemd service", "/etc/systemd/system/p0_agent_daemon.service"},
	}

	existingComponents := []string{}
	for _, comp := range components {
		if _, err := os.Stat(comp.path); err == nil {
			existingComponents = append(existingComponents, comp.name)
		}
	}

	if len(existingComponents) > 0 {
		fmt.Printf("⚠️  Found existing installation components:\n")
		for _, comp := range existingComponents {
			fmt.Printf("  - %s\n", comp)
		}
		fmt.Println()
		fmt.Println("Use --force to overwrite existing installation")
		return fmt.Errorf("existing installation detected")
	}

	if verbose {
		fmt.Println("✅ No existing installation found")
	}
	return nil
}

func installComponentDependencies(repoDir string, verbose, dryRun bool) error {
	fmt.Println("🔧 Installing component dependencies...")

	if dryRun {
		fmt.Println("[DRY RUN] Would install component dependencies")
		return nil
	}

	// Define components in dependency order
	components := []struct {
		name string
		dir  string
	}{
		{"daemon", "daemon"},
		{"NSS socket module", "nss_socket"},
		{"NSS cache module", "nss_cache"},
		{"PAM module", "pam"},
		{"SSH module", "sshd"},
		{"sudo configuration", "sudo"},
	}

	for i, comp := range components {
		fmt.Printf("  [%d/%d] Installing %s dependencies...", i+1, len(components), comp.name)
		if !verbose {
			fmt.Print(" ")
		} else {
			fmt.Println()
		}

		if err := runMakeCommand(repoDir, comp.dir, "install-deps", verbose); err != nil {
			return fmt.Errorf("failed to install dependencies for %s: %w", comp.name, err)
		}

		if !verbose {
			fmt.Println("✅")
		} else {
			fmt.Printf("✅ %s dependencies installed successfully\n", comp.name)
		}
	}

	return nil
}

func buildComponents(repoDir string, verbose, dryRun bool) error {
	fmt.Println("🔨 Building components...")

	if dryRun {
		fmt.Println("[DRY RUN] Would build all components individually")
		return nil
	}

	// Define components in installation order
	components := []struct {
		name string
		dir  string
	}{
		{"daemon", "daemon"},
		{"NSS socket module", "nss_socket"},
		{"NSS cache module", "nss_cache"},
		{"PAM module", "pam"},
		{"SSH module", "sshd"},
		{"sudo configuration", "sudo"},
	}

	for i, comp := range components {
		fmt.Printf("  [%d/%d] Building %s...", i+1, len(components), comp.name)
		if !verbose {
			fmt.Print(" ")
		} else {
			fmt.Println()
		}

		// Build the component (dependencies already installed)
		buildTarget := "build"

		if err := runMakeCommand(repoDir, comp.dir, buildTarget, verbose); err != nil {
			return fmt.Errorf("failed to build %s: %w", comp.name, err)
		}

		if !verbose {
			fmt.Println("✅")
		} else {
			fmt.Printf("✅ %s built successfully\n", comp.name)
		}
	}

	if verbose {
		fmt.Println("✅ All components built successfully")
	}
	return nil
}

func installComponents(repoDir string, verbose, dryRun bool) error {
	fmt.Println("📦 Installing components...")

	if dryRun {
		fmt.Println("[DRY RUN] Would install all components individually")
		return nil
	}

	// Define components in installation order (dependencies first)
	components := []struct {
		name string
		dir  string
	}{
		{"daemon", "daemon"},
		{"NSS socket module", "nss_socket"},
		{"NSS cache module", "nss_cache"},
		{"PAM module", "pam"},
		{"SSH module", "sshd"},
		{"sudo configuration", "sudo"},
	}

	for i, comp := range components {
		fmt.Printf("  [%d/%d] Installing %s...", i+1, len(components), comp.name)
		if !verbose {
			fmt.Print(" ")
		} else {
			fmt.Println()
		}

		if err := runMakeCommand(repoDir, comp.dir, "install", verbose); err != nil {
			return fmt.Errorf("failed to install %s: %w", comp.name, err)
		}

		if !verbose {
			fmt.Println("✅")
		} else {
			fmt.Printf("✅ %s installed successfully\n", comp.name)
		}
	}

	if verbose {
		fmt.Println("✅ All components installed successfully")
	}
	return nil
}

// runMakeCommand executes a make command in a specific component directory
func runMakeCommand(repoDir, componentDir, target string, verbose bool) error {
	cmd := exec.Command("make", target)
	cmd.Dir = filepath.Join(repoDir, componentDir)

	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		// Still capture errors even in non-verbose mode
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make %s failed in %s: %w", target, componentDir, err)
	}

	return nil
}

func verifyInstallation(verbose, dryRun bool) error {
	fmt.Print("🔍 Verifying installation...")
	if !verbose {
		fmt.Print(" ")
	} else {
		fmt.Println()
	}

	if dryRun {
		fmt.Println("[DRY RUN] Would verify installation")
		return nil
	}

	criticalFiles := []string{
		"/usr/local/bin/p0_agent_daemon",
		"/etc/systemd/system/p0_agent_daemon.service",
		"/etc/p0_agent/config.yaml",
		"/tmp/p0_agent", // Cache directory for NSS cache module
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err != nil {
			return fmt.Errorf("critical file missing: %s", file)
		}
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	if !verbose {
		fmt.Println("✅")
	} else {
		fmt.Println("✅ Installation verification completed")
	}
	return nil
}

func generateJWKKeyPair(verbose, dryRun bool) error {
	fmt.Print("🔐 Generating JWK key pair...")
	if !verbose {
		fmt.Print(" ")
	} else {
		fmt.Println()
	}

	if dryRun {
		fmt.Println("[DRY RUN] Would generate JWK key pair in /etc/p0_agent/")
		return nil
	}

	configDir := "/etc/p0_agent"

	// Generate JWK key pair
	keyPair, err := utils.GenerateJWKKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if verbose {
		fmt.Printf("   Generated key ID: %s\n", keyPair.KeyID)
	}

	// Save key pair to config directory
	if err := utils.SaveJWKKeyPair(keyPair, configDir); err != nil {
		return fmt.Errorf("failed to save key pair: %w", err)
	}

	if !verbose {
		fmt.Println("✅")
	} else {
		fmt.Println("✅ JWK key pair generated and saved successfully")
		fmt.Printf("   Private key: %s/jwk_private_key.json\n", configDir)
		fmt.Printf("   Public key: %s/jwk_public_key.json\n", configDir)
	}

	return nil
}
