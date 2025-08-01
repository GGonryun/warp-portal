package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var nextCmd = &cobra.Command{
	Use:   "next",
	Short: "Show next steps after installation",
	Long:  `Display the post-installation instructions for configuring and starting Warp Portal.`,
	Run: func(cmd *cobra.Command, args []string) {
		printNextSteps()
	},
}

func init() {
	rootCmd.AddCommand(nextCmd)
}

func printNextSteps() {
	fmt.Println()
	fmt.Println("📋 Next steps:")
	fmt.Println("  1. Configure /etc/warp_portal/config.yaml")
	fmt.Println("  2. Run 'portal register' to register with P0 backend")
	fmt.Println("  3. Start the daemon: systemctl start warp_portal_daemon")
	fmt.Println("  4. ⚠️  RESTART SSH service: sudo systemctl restart sshd")
	fmt.Println("     (Required for SSH authentication to work)")
	fmt.Println("  5. Check status: portal status")
	fmt.Println()
}