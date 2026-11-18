package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the PermTracer service",
	Long: `Manage the PermTracer as a system service.

On Windows, this installs/manages a Windows Service.
On Linux, this generates systemd unit files.

Examples:
  permtracer service install --ldap-url ldaps://dc.example.com:636
  permtracer service start
  permtracer service stop
  permtracer service status
  permtracer service uninstall`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install PermTracer as a system service",
	Long: `Install PermTracer as a system service.

On Windows, this creates a Windows Service that starts automatically.
On Linux, this creates a systemd unit file.

The service will use the configuration from:
- Command line flags (stored in service config)
- Environment variables
- Config file (./config.yaml or /etc/permtracer/config.yaml)`,
	RunE: runServiceInstall,
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the PermTracer service",
	RunE:  runServiceUninstall,
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the PermTracer service",
	RunE:  runServiceStart,
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the PermTracer service",
	RunE:  runServiceStop,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the PermTracer service",
	RunE:  runServiceStatus,
}

var serviceRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run the service (called by service manager)",
	Hidden: true, // Hidden as it's called by Windows Service Manager
	RunE:   runServiceRun,
}

// Service configuration flags
var (
	svcLdapURL      string
	svcLdapBindDN   string
	svcLdapBindPass string
	svcLdapBaseDN   string
	svcLdapTLSSkip  bool
	svcPort         int
)

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
	serviceCmd.AddCommand(serviceRunCmd)

	// Install command flags
	serviceInstallCmd.Flags().StringVar(&svcLdapURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc.example.com:636)")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindDN, "ldap-bind-dn", "", "LDAP bind DN")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindPass, "ldap-bind-password", "", "LDAP bind password")
	serviceInstallCmd.Flags().StringVar(&svcLdapBaseDN, "ldap-base-dn", "", "LDAP base DN for searches")
	serviceInstallCmd.Flags().BoolVar(&svcLdapTLSSkip, "ldap-tls-skip-verify", false, "Skip LDAP TLS certificate verification")
	serviceInstallCmd.Flags().IntVar(&svcPort, "port", 8443, "API server port")
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	// As in server.go's runServer: --ldap-bind-password puts the LDAP
	// bind secret in argv, readable by any local user via /proc/<pid>/cmdline for
	// as long as this install command runs. svcLdapBindPass is never read back
	// from viper, so LDAP_BIND_PASSWORD/config.yaml are not an alternative here
	// either - on Linux, installLinuxService below doesn't even consume this
	// value (LDAP is left for the admin GUI or a manual config.yaml edit).
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line - the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). Omit it and configure LDAP afterwards via the admin GUI or by editing config.yaml directly instead.")
	}

	if runtime.GOOS == "windows" {
		return installWindowsService()
	}
	return installLinuxService()
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return uninstallService()
	}
	return uninstallLinuxService()
}

func runServiceStart(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return startWindowsService()
	}
	return startLinuxService()
}

func runServiceStop(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return stopWindowsService()
	}
	return stopLinuxService()
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return statusWindowsService()
	}
	return statusLinuxService()
}

func runServiceRun(cmd *cobra.Command, args []string) error {
	// This is called by Windows Service Manager
	return runService(false)
}

// linuxLegacyServiceNames are the systemd unit names earlier versions of this
// product used, before it was renamed PermTracer: "etc-collector" (the
// original, unhardened unit of this command tree) and "etcsec-collector" (the
// unit `install` created). Kept only so uninstallLinuxService can still clean
// up a unit an older binary left behind; nothing is written under these names.
var linuxLegacyServiceNames = []string{"etc-collector", "etcsec-collector"}

// Linux service management using systemd.
//
// installLinuxService delegates to installLinuxSystemdService (install.go),
// the same function `permtracer install` uses, so both paths create one
// hardened unit under one name.
//
// mode is hardcoded to "server": this command's own flags and docs only ever
// implied standalone server mode (`server --port N`), not `daemon`.
func installLinuxService() error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cfgDir, _, _ := resolvePlatformPaths()

	if err := installLinuxSystemdService(binPath, cfgDir, "server", fmt.Sprintf("--port %d", svcPort)); err != nil {
		return err
	}

	fmt.Println("Service installed successfully")
	fmt.Printf("Configure LDAP via the admin GUI, or edit %s\n", filepath.Join(cfgDir, "config.yaml"))
	fmt.Println("Then run: permtracer service start")
	return nil
}

func uninstallLinuxService() error {
	exec.Command("systemctl", "stop", "permtracer").Run()
	exec.Command("systemctl", "disable", "permtracer").Run()

	unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	// Best-effort cleanup of units an older binary may have created under a
	// former product name - never written by this binary, but nothing else
	// will ever remove them either.
	for _, legacy := range linuxLegacyServiceNames {
		exec.Command("systemctl", "stop", legacy).Run()
		exec.Command("systemctl", "disable", legacy).Run()
		os.Remove(filepath.Join(linuxServiceDir, legacy+".service"))
	}

	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("Service uninstalled successfully")
	return nil
}

func startLinuxService() error {
	cmd := exec.Command("systemctl", "start", "permtracer")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	fmt.Println("Service started")
	return nil
}

func stopLinuxService() error {
	cmd := exec.Command("systemctl", "stop", "permtracer")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	fmt.Println("Service stopped")
	return nil
}

func statusLinuxService() error {
	cmd := exec.Command("systemctl", "status", "permtracer")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // Ignore error, status returns non-zero if not running
	return nil
}
