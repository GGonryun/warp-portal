package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DefaultCacheDirectory = "/tmp/warp_portal"
	PasswdCacheFile      = "passwd.cache"
	GroupCacheFile       = "group.cache"
)

var clearCacheCmd = &cobra.Command{
	Use:   "clear-cache",
	Short: "Wipe out all caches (NSS cache files and daemon HTTP cache)",
	Long: `Clear all caches used by Warp Portal including:
- NSS cache files (passwd.cache, group.cache) 
- Daemon HTTP cache proxy (by restarting the daemon service)

This command will remove all cached user and group data, forcing fresh lookups from the backend provider.`,
	RunE: clearCache,
}

func init() {
	rootCmd.AddCommand(clearCacheCmd)
	clearCacheCmd.Flags().BoolP("force", "f", false, "Force cache clearing without confirmation")
	clearCacheCmd.Flags().StringP("cache-dir", "d", DefaultCacheDirectory, "Cache directory path")
}

func clearCache(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	dryRun := viper.GetBool("dry-run")
	verbose := viper.GetBool("verbose")

	if verbose {
		fmt.Printf("Cache directory: %s\n", cacheDir)
		fmt.Printf("Dry run: %v\n", dryRun)
	}

	if !force {
		fmt.Print("This will clear all cached user and group data. Continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" && response != "Yes" {
			fmt.Println("Cache clearing cancelled.")
			return nil
		}
	}

	var errors []error

	// Clear NSS cache files
	if err := clearNSSCacheFiles(cacheDir, dryRun, verbose); err != nil {
		errors = append(errors, fmt.Errorf("failed to clear NSS cache files: %w", err))
	}

	// Clear daemon HTTP cache by sending reload signal
	if err := reloadDaemon(dryRun, verbose); err != nil {
		errors = append(errors, fmt.Errorf("failed to reload daemon cache: %w", err))
	}

	if len(errors) > 0 {
		fmt.Println("Cache clearing completed with some errors:")
		for _, err := range errors {
			fmt.Printf("  - %v\n", err)
		}
		return fmt.Errorf("cache clearing completed with %d errors", len(errors))
	}

	if !dryRun {
		fmt.Println("All caches cleared successfully.")
	} else {
		fmt.Println("Dry run completed - no changes made.")
	}

	return nil
}

func clearNSSCacheFiles(cacheDir string, dryRun, verbose bool) error {
	cacheFiles := []string{
		filepath.Join(cacheDir, PasswdCacheFile),
		filepath.Join(cacheDir, GroupCacheFile),
	}

	for _, file := range cacheFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			if verbose {
				fmt.Printf("Cache file does not exist: %s\n", file)
			}
			continue
		}

		if verbose {
			fmt.Printf("Removing cache file: %s\n", file)
		}

		if !dryRun {
			if err := os.Remove(file); err != nil {
				return fmt.Errorf("failed to remove %s: %w", file, err)
			}
		}
	}

	// Also remove any .tmp files
	if !dryRun {
		tmpPattern := filepath.Join(cacheDir, "*.tmp")
		matches, err := filepath.Glob(tmpPattern)
		if err == nil {
			for _, match := range matches {
				if verbose {
					fmt.Printf("Removing temporary file: %s\n", match)
				}
				os.Remove(match) // Best effort, don't fail on error
			}
		}
	}

	return nil
}

func reloadDaemon(dryRun, verbose bool) error {
	if verbose {
		fmt.Println("Attempting to reload daemon to clear HTTP cache...")
	}

	if dryRun {
		fmt.Println("Would send reload signal to warp-portal-daemon service")
		return nil
	}

	// Try systemctl reload first (most common)
	if err := runCommand("systemctl", "reload", "warp-portal-daemon"); err == nil {
		if verbose {
			fmt.Println("Daemon reloaded via systemctl")
		}
		return nil
	}

	// Try pkill with SIGUSR1 (reload signal)
	if err := runCommand("pkill", "-SIGUSR1", "warp-portal-daemon"); err == nil {
		if verbose {
			fmt.Println("Sent reload signal to daemon via pkill")
		}
		return nil
	}

	// If we can't reload, inform user but don't fail
	fmt.Println("Warning: Could not reload daemon to clear HTTP cache. NSS cache files cleared successfully.")
	fmt.Println("To clear daemon HTTP cache, manually restart the warp-portal-daemon service:")
	fmt.Println("  sudo systemctl restart warp-portal-daemon")
	
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}