package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cli/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	uninstallKeepConfig bool
	uninstallKeepLogs   bool
	uninstallRepo       string
	uninstallBranch     string
)

// uninstallCmd represents the uninstall command
var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove P0 Agent system components",
	Long: `Remove all P0 Agent components from the system including:
- Daemon binary and systemd service
- NSS module and configuration
- PAM module and configuration  
- SSH module
- Sudo configuration and groups

This command will:
1. Stop running services
2. Remove installed binaries and libraries
3. Restore system configuration backups
4. Remove systemd service files
5. Clean up logs and temporary files

System configuration backups will be restored automatically.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip root check for dry-run
		dryRun := viper.GetBool("dry-run")
		if !dryRun && os.Geteuid() != 0 {
			return fmt.Errorf("uninstallation requires root privileges. Please run with sudo")
		}
		return nil
	},
	RunE: runUninstall,
}

func init() {
	rootCmd.AddCommand(uninstallCmd)

	uninstallCmd.Flags().BoolVar(&uninstallKeepConfig, "keep-config", false, "Keep configuration files")
	uninstallCmd.Flags().BoolVar(&uninstallKeepLogs, "keep-logs", false, "Keep log files")
	uninstallCmd.Flags().StringVar(&uninstallRepo, "repo", config.DefaultRepository, "Git repository URL for uninstall makefiles")
	uninstallCmd.Flags().StringVar(&uninstallBranch, "branch", config.DefaultBranch, "Git branch to clone for uninstall makefiles")
}

func runUninstall(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")
	dryRun := viper.GetBool("dry-run")

	if verbose {
		fmt.Println("🗑️  Starting P0 Agent uninstallation...")
		fmt.Printf("Repository: %s\n", uninstallRepo)
		fmt.Printf("Branch: %s\n", uninstallBranch)
		fmt.Printf("Keep config: %t\n", uninstallKeepConfig)
		fmt.Printf("Keep logs: %t\n", uninstallKeepLogs)
		fmt.Printf("Dry run: %t\n", dryRun)
		fmt.Println()
	}

	// Confirm uninstallation unless dry-run
	if !dryRun {
		fmt.Print("⚠️  This will remove all P0 Agent components from your system.\n")
		fmt.Print("Are you sure you want to continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))

		if response != "y" && response != "yes" {
			fmt.Println("Uninstallation cancelled.")
			return nil
		}
		fmt.Println()
	}

	// Step 1: Stop services
	if err := stopServices(verbose, dryRun); err != nil {
		fmt.Printf("⚠️  Warning: failed to stop services: %v\n", err)
	}

	// Step 2: Check if we have a repository to use for uninstall
	tempDir, repoDir, err := setupUninstallRepo(verbose, dryRun)
	if err != nil {
		// Fallback to manual uninstall
		if verbose {
			fmt.Println("⚠️  Repository not available, proceeding with manual uninstall...")
		}
		return manualUninstall(verbose, dryRun)
	}
	defer func() {
		if tempDir != "" {
			if err := os.RemoveAll(tempDir); err != nil && verbose {
				fmt.Printf("⚠️  Warning: failed to clean up temporary directory %s: %v\n", tempDir, err)
			} else if verbose {
				fmt.Printf("🧹 Cleaned up temporary directory: %s\n", tempDir)
			}
		}
	}()

	// Step 3: Use makefile uninstall
	if err := makefileUninstall(repoDir, verbose, dryRun); err != nil {
		fmt.Printf("⚠️  Makefile uninstall failed: %v\n", err)
		fmt.Println("Falling back to manual uninstall...")
		return manualUninstall(verbose, dryRun)
	}

	// Step 4: Clean up additional files
	if err := cleanupAdditionalFiles(verbose, dryRun); err != nil {
		fmt.Printf("⚠️  Warning: cleanup failed: %v\n", err)
	}

	// Step 5: Verify uninstallation
	if err := verifyUninstallation(verbose, dryRun); err != nil {
		fmt.Printf("⚠️  Some components may still be present: %v\n", err)
	}

	fmt.Println()
	fmt.Println("✅ P0 Agent uninstallation completed!")
	fmt.Println()
	if !uninstallKeepConfig {
		fmt.Println("📄 Configuration files have been removed")
	}
	if !uninstallKeepLogs {
		fmt.Println("📋 Log files have been removed")
	}
	fmt.Println("🔄 System configuration files have been restored from backups")

	return nil
}

func stopServices(verbose, dryRun bool) error {
	if verbose {
		fmt.Println("🛑 Stopping services...")
	}

	services := []string{
		"p0_agent_daemon.service",
		"p0-agent-daemon.service",
	}

	for _, service := range services {
		if dryRun {
			fmt.Printf("[DRY RUN] Would stop service: %s\n", service)
			continue
		}

		// Check if service exists and is active
		cmd := exec.Command("systemctl", "is-active", service)
		if err := cmd.Run(); err != nil {
			continue // Service not active or doesn't exist
		}

		// Stop the service
		cmd = exec.Command("systemctl", "stop", service)
		if err := cmd.Run(); err != nil && verbose {
			fmt.Printf("⚠️  Warning: failed to stop %s: %v\n", service, err)
		} else if verbose {
			fmt.Printf("✅ Stopped service: %s\n", service)
		}
	}

	return nil
}

func setupUninstallRepo(verbose, dryRun bool) (string, string, error) {
	// Try to use the same repository setup as install
	tempDir, err := os.MkdirTemp("", "p0-agent-uninstall-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	if verbose {
		fmt.Printf("📁 Created temporary directory: %s\n", tempDir)
		fmt.Printf("📥 Cloning repository %s (branch: %s) for uninstall makefiles...\n", uninstallRepo, uninstallBranch)
	}

	if dryRun {
		fmt.Printf("[DRY RUN] Would clone: git clone --branch %s --depth 1 %s\n", uninstallBranch, uninstallRepo)
		return tempDir, filepath.Join(tempDir, "p0-agent"), nil
	}

	// Use the configured repo URL and branch
	cmd := exec.Command("git", "clone", "--branch", uninstallBranch, "--depth", "1", uninstallRepo, "p0-agent")
	cmd.Dir = tempDir

	if err := cmd.Run(); err != nil {
		return tempDir, "", fmt.Errorf("failed to clone repository: %w", err)
	}

	repoDir := filepath.Join(tempDir, "p0-agent")
	if verbose {
		fmt.Println("✅ Repository cloned for uninstall")
	}

	return tempDir, repoDir, nil
}

func makefileUninstall(repoDir string, verbose, dryRun bool) error {
	if verbose {
		fmt.Println("📦 Running makefile uninstall...")
	}

	if dryRun {
		fmt.Println("[DRY RUN] Would run: make uninstall")
		return nil
	}

	cmd := exec.Command("make", "uninstall")
	cmd.Dir = repoDir
	cmd.Stdin = strings.NewReader("y\n") // Auto-confirm uninstall
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make uninstall failed: %w", err)
	}

	if verbose {
		fmt.Println("✅ Makefile uninstall completed")
	}
	return nil
}

func manualUninstall(verbose, dryRun bool) error {
	if verbose {
		fmt.Println("🔧 Performing manual uninstall...")
	}

	// Define components to remove
	components := []struct {
		name  string
		paths []string
	}{
		{
			name: "Daemon binary",
			paths: []string{
				"/usr/local/bin/p0_agent_daemon",
				"/usr/bin/p0_agent_daemon",
			},
		},
		{
			name: "NSS module",
			paths: []string{
				"/usr/lib/x86_64-linux-gnu/libnss_socket.so.2",
				"/usr/lib/libnss_socket.so.2",
				"/lib/x86_64-linux-gnu/libnss_socket.so.2",
				"/lib/libnss_socket.so.2",
			},
		},
		{
			name: "PAM module",
			paths: []string{
				"/lib/x86_64-linux-gnu/security/pam_sockauth.so",
				"/lib64/security/pam_sockauth.so",
				"/lib/security/pam_sockauth.so",
				"/usr/lib/x86_64-linux-gnu/security/pam_sockauth.so",
				"/usr/lib64/security/pam_sockauth.so",
				"/usr/lib/security/pam_sockauth.so",
			},
		},
		{
			name: "SSH module",
			paths: []string{
				"/usr/local/bin/authorized_keys_socket",
				"/usr/bin/authorized_keys_socket",
			},
		},
		{
			name: "Systemd service",
			paths: []string{
				"/etc/systemd/system/p0_agent_daemon.service",
				"/etc/systemd/system/p0-agent-daemon.service",
			},
		},
	}

	// Remove component files
	for _, component := range components {
		if verbose {
			fmt.Printf("🗑️  Removing %s...\n", component.name)
		}

		for _, path := range component.paths {
			if dryRun {
				if _, err := os.Stat(path); err == nil {
					fmt.Printf("[DRY RUN] Would remove: %s\n", path)
				}
				continue
			}

			if _, err := os.Stat(path); err == nil {
				if err := os.Remove(path); err != nil && verbose {
					fmt.Printf("⚠️  Warning: failed to remove %s: %v\n", path, err)
				} else if verbose {
					fmt.Printf("✅ Removed: %s\n", path)
				}
			}
		}
	}

	// Restore configuration backups
	if err := restoreConfigBackups(verbose, dryRun); err != nil && verbose {
		fmt.Printf("⚠️  Warning: failed to restore some backups: %v\n", err)
	}

	// Reload systemd
	if !dryRun {
		cmd := exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil && verbose {
			fmt.Printf("⚠️  Warning: failed to reload systemd: %v\n", err)
		}
	}

	if verbose {
		fmt.Println("✅ Manual uninstall completed")
	}
	return nil
}

func restoreConfigBackups(verbose, dryRun bool) error {
	if verbose {
		fmt.Println("🔄 Restoring configuration backups...")
	}

	backupRestores := []struct {
		configPath string
		backupGlob string
	}{
		{"/etc/nsswitch.conf", "/etc/nsswitch.conf.bak.*"},
		{"/etc/pam.d/sudo", "/etc/pam.d/sudo.bak.*"},
		{"/etc/pam.d/su", "/etc/pam.d/su.bak.*"},
		{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.bak.*"},
		{"/etc/sudoers", "/etc/sudoers.bak.*"},
	}

	for _, restore := range backupRestores {
		if dryRun {
			fmt.Printf("[DRY RUN] Would restore backups for: %s\n", restore.configPath)
			continue
		}

		// Find the most recent backup
		matches, err := filepath.Glob(restore.backupGlob)
		if err != nil || len(matches) == 0 {
			continue
		}

		// Use the most recent backup (lexicographically last due to timestamp)
		latestBackup := matches[len(matches)-1]

		// Restore the backup
		if err := copyFile(latestBackup, restore.configPath); err != nil && verbose {
			fmt.Printf("⚠️  Warning: failed to restore %s from %s: %v\n", restore.configPath, latestBackup, err)
		} else if verbose {
			fmt.Printf("✅ Restored %s from %s\n", restore.configPath, latestBackup)
		}
	}

	return nil
}

func cleanupAdditionalFiles(verbose, dryRun bool) error {
	if verbose {
		fmt.Println("🧹 Cleaning up additional files...")
	}

	// Files and directories to clean up
	cleanupItems := []string{}

	if !uninstallKeepConfig {
		cleanupItems = append(cleanupItems,
			"/etc/p0_agent",
		)
	}

	if !uninstallKeepLogs {
		cleanupItems = append(cleanupItems,
			"/var/log/p0_agent_daemon.log",
			"/var/log/p0_agent.log",
			"/var/log/nss_socket.log",
			"/var/log/pam_sockauth.log",
		)
	}

	// Runtime files
	cleanupItems = append(cleanupItems,
		"/run/p0_agent.sock",
		"/run/p0_agent_daemon.pid",
	)

	for _, item := range cleanupItems {
		if dryRun {
			if _, err := os.Stat(item); err == nil {
				fmt.Printf("[DRY RUN] Would remove: %s\n", item)
			}
			continue
		}

		if info, err := os.Stat(item); err == nil {
			if info.IsDir() {
				if err := os.RemoveAll(item); err != nil && verbose {
					fmt.Printf("⚠️  Warning: failed to remove directory %s: %v\n", item, err)
				} else if verbose {
					fmt.Printf("✅ Removed directory: %s\n", item)
				}
			} else {
				if err := os.Remove(item); err != nil && verbose {
					fmt.Printf("⚠️  Warning: failed to remove file %s: %v\n", item, err)
				} else if verbose {
					fmt.Printf("✅ Removed file: %s\n", item)
				}
			}
		}
	}

	return nil
}

func verifyUninstallation(verbose, dryRun bool) error {
	if verbose {
		fmt.Println("🔍 Verifying uninstallation...")
	}

	if dryRun {
		fmt.Println("[DRY RUN] Would verify uninstallation")
		return nil
	}

	// Check that key components are removed
	criticalFiles := []string{
		"/usr/local/bin/p0_agent_daemon",
		"/etc/systemd/system/p0_agent_daemon.service",
	}

	remainingFiles := []string{}
	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			remainingFiles = append(remainingFiles, file)
		}
	}

	if len(remainingFiles) > 0 {
		return fmt.Errorf("some files still exist: %v", remainingFiles)
	}

	if verbose {
		fmt.Println("✅ Uninstallation verification completed")
	}
	return nil
}

// Helper function to copy files
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
