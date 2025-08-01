package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var nextCmd = &cobra.Command{
	Use:   "next",
	Short: "Show next steps after installation",
	Long:  `Display the post-installation instructions for configuring and starting P0 Agent.`,
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
	fmt.Println("  1. Configure /etc/p0_agent/config.yaml")
	fmt.Println("  2. Run 'p0 register' to register with P0 backend")
	fmt.Println("  3. Start the daemon: systemctl start p0_agent_daemon")
	fmt.Println("  4. ⚠️  RESTART SSH service: sudo systemctl restart sshd")
	fmt.Println("     (Required for SSH authentication to work)")
	fmt.Println("  5. Check status: p0 status")
	fmt.Println()
}
