package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	statusJSON   bool
	statusQuiet  bool
	statusWatch  bool
	statusDetail bool
)

type SystemStatus struct {
	Overall      string             `json:"overall"`
	Timestamp    time.Time          `json:"timestamp"`
	Installation InstallationStatus `json:"installation"`
	Services     ServiceStatus      `json:"services"`
	Registration RegistrationStatus `json:"registration"`
	Components   ComponentStatus    `json:"components"`
}

type InstallationStatus struct {
	Installed bool     `json:"installed"`
	Version   string   `json:"version,omitempty"`
	Missing   []string `json:"missing,omitempty"`
}

type ServiceStatus struct {
	Daemon DaemonStatus `json:"daemon"`
	Socket SocketStatus `json:"socket"`
}

type DaemonStatus struct {
	Running bool   `json:"running"`
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
	PID     int    `json:"pid,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
}

type SocketStatus struct {
	Active bool   `json:"active"`
	Path   string `json:"path"`
}

type RegistrationStatus struct {
	Registered bool   `json:"registered"`
	AgentID    string `json:"agent_id,omitempty"`
	Backend    string `json:"backend,omitempty"`
	LastPing   string `json:"last_ping,omitempty"`
}

type ComponentStatus struct {
	NSS  ComponentInfo `json:"nss"`
	PAM  ComponentInfo `json:"pam"`
	SSH  ComponentInfo `json:"ssh"`
	Sudo ComponentInfo `json:"sudo"`
}

type ComponentInfo struct {
	Installed  bool   `json:"installed"`
	Configured bool   `json:"configured"`
	Status     string `json:"status"`
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon and registration state",
	Long: `Display comprehensive status information about the Warp Portal system including:

- Installation status of all components
- Service status (daemon, socket)
- Registration status with P0 backend  
- Component configuration status (NSS, PAM, SSH, sudo)
- System health and connectivity

Use --json for machine-readable output or --watch for continuous monitoring.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)

	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output status in JSON format")
	statusCmd.Flags().BoolVar(&statusQuiet, "quiet", false, "Only show overall status")
	statusCmd.Flags().BoolVar(&statusWatch, "watch", false, "Continuously monitor status (Ctrl+C to exit)")
	statusCmd.Flags().BoolVar(&statusDetail, "detail", false, "Show detailed status information")
}

func runStatus(cmd *cobra.Command, args []string) error {
	verbose := viper.GetBool("verbose")

	if statusWatch {
		return runWatchStatus(verbose)
	}

	status, err := collectStatus(verbose)
	if err != nil {
		return fmt.Errorf("failed to collect status: %w", err)
	}

	if statusJSON {
		return outputStatusJSON(status)
	}

	return outputStatusHuman(status, verbose)
}

func runWatchStatus(verbose bool) error {
	fmt.Println("🔄 Monitoring Warp Portal status (Press Ctrl+C to exit)...")
	fmt.Println()

	for {
		fmt.Print("\033[2J\033[H")

		fmt.Printf("Warp Portal Status - %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println(strings.Repeat("=", 50))

		status, err := collectStatus(verbose)
		if err != nil {
			fmt.Printf("❌ Error collecting status: %v\n", err)
		} else {
			outputStatusHuman(status, false) // Don't be verbose in watch mode
		}

		fmt.Println()
		fmt.Println("Refreshing in 5 seconds... (Ctrl+C to exit)")

		time.Sleep(5 * time.Second)
	}
}

func collectStatus(verbose bool) (*SystemStatus, error) {
	status := &SystemStatus{
		Timestamp: time.Now(),
	}

	installStatus, err := checkInstallationStatus(verbose)
	if err != nil && verbose {
		fmt.Printf("Warning: failed to check installation: %v\n", err)
	}
	status.Installation = installStatus

	serviceStatus, err := checkServiceStatus(verbose)
	if err != nil && verbose {
		fmt.Printf("Warning: failed to check services: %v\n", err)
	}
	status.Services = serviceStatus

	regStatus, err := checkRegistrationStatus(verbose)
	if err != nil && verbose {
		fmt.Printf("Warning: failed to check registration: %v\n", err)
	}
	status.Registration = regStatus

	compStatus, err := checkComponentStatus(verbose)
	if err != nil && verbose {
		fmt.Printf("Warning: failed to check components: %v\n", err)
	}
	status.Components = compStatus

	status.Overall = determineOverallStatus(status)

	return status, nil
}

func checkInstallationStatus(verbose bool) (InstallationStatus, error) {
	status := InstallationStatus{}

	requiredFiles := []string{
		"/usr/local/bin/warp_portal_daemon",
		"/etc/systemd/system/warp_portal_daemon.service",
		"/etc/warp_portal/config.yaml",
	}

	missing := []string{}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); err != nil {
			missing = append(missing, file)
		}
	}

	status.Installed = len(missing) == 0
	status.Missing = missing

	if status.Installed {
		if version, err := getDaemonVersion(); err == nil {
			status.Version = version
		}
	}

	return status, nil
}

func checkServiceStatus(verbose bool) (ServiceStatus, error) {
	status := ServiceStatus{}

	daemonStatus, err := checkDaemonService(verbose)
	if err != nil {
		return status, err
	}
	status.Daemon = daemonStatus

	socketStatus := checkSocket(verbose)
	status.Socket = socketStatus

	return status, nil
}

func checkDaemonService(verbose bool) (DaemonStatus, error) {
	status := DaemonStatus{}

	cmd := exec.Command("systemctl", "is-active", "warp_portal_daemon.service")
	if err := cmd.Run(); err == nil {
		status.Running = true
		status.Status = "active"
	} else {
		status.Running = false
		status.Status = "inactive"
	}

	cmd = exec.Command("systemctl", "is-enabled", "warp_portal_daemon.service")
	if err := cmd.Run(); err == nil {
		status.Enabled = true
	}

	if status.Running {
		if pid, err := getDaemonPID(); err == nil {
			status.PID = pid
			if uptime, err := getProcessUptime(pid); err == nil {
				status.Uptime = uptime
			}
		}
	}

	return status, nil
}

func checkSocket(verbose bool) SocketStatus {
	status := SocketStatus{
		Path: "/run/warp_portal.sock",
	}

	if _, err := os.Stat(status.Path); err == nil {
		if info, err := os.Stat(status.Path); err == nil {
			if info.Mode()&os.ModeSocket != 0 {
				status.Active = true
			}
		}
	}

	return status
}

func checkRegistrationStatus(verbose bool) (RegistrationStatus, error) {
	status := RegistrationStatus{}

	configPath := "/etc/warp_portal/config.yaml"
	if data, err := os.ReadFile(configPath); err == nil {
		configStr := string(data)

		if strings.Contains(configStr, "agent_id:") && strings.Contains(configStr, "backend_url:") {
			status.Registered = true

			lines := strings.Split(configStr, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "agent_id:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						status.AgentID = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				}
				if strings.HasPrefix(line, "backend_url:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						status.Backend = strings.Trim(strings.TrimSpace(parts[1]), "\"")
					}
				}
			}
		}
	}

	return status, nil
}

func checkComponentStatus(verbose bool) (ComponentStatus, error) {
	status := ComponentStatus{}

	status.NSS = checkNSSStatus()

	status.PAM = checkPAMStatus()

	status.SSH = checkSSHStatus()

	status.Sudo = checkSudoStatus()

	return status, nil
}

func checkNSSStatus() ComponentInfo {
	info := ComponentInfo{}

	nssPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libnss_socket.so.2",
		"/usr/lib/libnss_socket.so.2",
		"/lib/libnss_socket.so.2",
	}

	for _, path := range nssPaths {
		if _, err := os.Stat(path); err == nil {
			info.Installed = true
			break
		}
	}

	if data, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		if strings.Contains(string(data), "socket") {
			info.Configured = true
		}
	}

	if info.Installed && info.Configured {
		info.Status = "active"
	} else if info.Installed {
		info.Status = "installed"
	} else {
		info.Status = "missing"
	}

	return info
}

func checkPAMStatus() ComponentInfo {
	info := ComponentInfo{}

	pamPaths := []string{
		"/lib/x86_64-linux-gnu/security/pam_sockauth.so",
		"/lib64/security/pam_sockauth.so",
		"/lib/security/pam_sockauth.so",
	}

	for _, path := range pamPaths {
		if _, err := os.Stat(path); err == nil {
			info.Installed = true
			break
		}
	}

	pamFiles := []string{"/etc/pam.d/sudo", "/etc/pam.d/su"}
	for _, file := range pamFiles {
		if data, err := os.ReadFile(file); err == nil {
			if strings.Contains(string(data), "pam_sockauth.so") {
				info.Configured = true
				break
			}
		}
	}

	if info.Installed && info.Configured {
		info.Status = "active"
	} else if info.Installed {
		info.Status = "installed"
	} else {
		info.Status = "missing"
	}

	return info
}

func checkSSHStatus() ComponentInfo {
	info := ComponentInfo{}

	if _, err := os.Stat("/usr/local/bin/authorized_keys_socket"); err == nil {
		info.Installed = true
	}

	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		if strings.Contains(string(data), "authorized_keys_socket") {
			info.Configured = true
		}
	}

	if info.Installed && info.Configured {
		info.Status = "active"
	} else if info.Installed {
		info.Status = "installed"
	} else {
		info.Status = "missing"
	}

	return info
}

func checkSudoStatus() ComponentInfo {
	info := ComponentInfo{}

	cmd := exec.Command("getent", "group", "warp-portal-admin")
	if err := cmd.Run(); err == nil {
		info.Installed = true
	}

	if _, err := os.Stat("/etc/sudoers.d/warp-portal"); err == nil {
		info.Configured = true
	}

	if info.Installed && info.Configured {
		info.Status = "active"
	} else if info.Installed {
		info.Status = "installed"
	} else {
		info.Status = "missing"
	}

	return info
}

func determineOverallStatus(status *SystemStatus) string {
	if !status.Installation.Installed {
		return "not_installed"
	}

	if !status.Services.Daemon.Running {
		return "stopped"
	}

	if !status.Services.Socket.Active {
		return "degraded"
	}

	if !status.Registration.Registered {
		return "unregistered"
	}

	components := []ComponentInfo{
		status.Components.NSS,
		status.Components.PAM,
		status.Components.SSH,
		status.Components.Sudo,
	}

	allActive := true
	for _, comp := range components {
		if comp.Status != "active" {
			allActive = false
			break
		}
	}

	if allActive {
		return "healthy"
	}

	return "degraded"
}

func outputStatusJSON(status *SystemStatus) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputStatusHuman(status *SystemStatus, verbose bool) error {
	if statusQuiet {
		fmt.Println(status.Overall)
		return nil
	}

	statusEmoji := map[string]string{
		"healthy":       "✅",
		"degraded":      "⚠️",
		"stopped":       "🛑",
		"unregistered":  "📝",
		"not_installed": "❌",
	}

	emoji := statusEmoji[status.Overall]
	if emoji == "" {
		emoji = "❓"
	}

	fmt.Printf("%s Warp Portal Status: %s\n", emoji, strings.ToUpper(status.Overall))
	fmt.Println()

	fmt.Println("📦 Installation:")
	if status.Installation.Installed {
		fmt.Printf("  ✅ Installed")
		if status.Installation.Version != "" {
			fmt.Printf(" (v%s)", status.Installation.Version)
		}
		fmt.Println()
	} else {
		fmt.Println("  ❌ Not installed")
		if len(status.Installation.Missing) > 0 && statusDetail {
			fmt.Println("     Missing components:")
			for _, missing := range status.Installation.Missing {
				fmt.Printf("     - %s\n", missing)
			}
		}
	}
	fmt.Println()

	fmt.Println("🔧 Services:")
	daemonEmoji := "❌"
	if status.Services.Daemon.Running {
		daemonEmoji = "✅"
	}
	fmt.Printf("  %s Daemon: %s", daemonEmoji, status.Services.Daemon.Status)
	if status.Services.Daemon.Running && status.Services.Daemon.PID > 0 {
		fmt.Printf(" (PID: %d", status.Services.Daemon.PID)
		if status.Services.Daemon.Uptime != "" {
			fmt.Printf(", uptime: %s", status.Services.Daemon.Uptime)
		}
		fmt.Printf(")")
	}
	fmt.Println()

	socketEmoji := "❌"
	if status.Services.Socket.Active {
		socketEmoji = "✅"
	}
	fmt.Printf("  %s Socket: %s\n", socketEmoji, status.Services.Socket.Path)
	fmt.Println()

	fmt.Println("📝 Registration:")
	if status.Registration.Registered {
		fmt.Printf("  ✅ Registered")
		if status.Registration.AgentID != "" {
			fmt.Printf(" (ID: %s)", status.Registration.AgentID)
		}
		fmt.Println()
		if status.Registration.Backend != "" && statusDetail {
			fmt.Printf("     Backend: %s\n", status.Registration.Backend)
		}
	} else {
		fmt.Println("  ❌ Not registered")
	}
	fmt.Println()

	fmt.Println("🔗 Components:")
	components := map[string]ComponentInfo{
		"NSS":  status.Components.NSS,
		"PAM":  status.Components.PAM,
		"SSH":  status.Components.SSH,
		"Sudo": status.Components.Sudo,
	}

	for name, comp := range components {
		emoji := "❌"
		if comp.Status == "active" {
			emoji = "✅"
		} else if comp.Status == "installed" {
			emoji = "⚠️"
		}
		fmt.Printf("  %s %s: %s\n", emoji, name, comp.Status)
	}

	return nil
}

func getDaemonVersion() (string, error) {
	cmd := exec.Command("/usr/local/bin/warp_portal_daemon", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getDaemonPID() (int, error) {
	data, err := os.ReadFile("/run/warp_portal_daemon.pid")
	if err != nil {
		return 0, err
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return 0, err
	}

	return pid, nil
}

func getProcessUptime(pid int) (string, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return "", err
	}

	if err := process.Signal(syscall.Signal(0)); err != nil {
		return "", fmt.Errorf("process not running")
	}

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return "", fmt.Errorf("invalid stat format")
	}

	return "unknown", nil
}
