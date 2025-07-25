# Portal CLI

A command-line interface for managing the Warp Portal authentication system.

## Overview

The Portal CLI provides a unified interface for installing, configuring, and managing all Warp Portal components including:

- **Daemon**: Core Go service that handles authentication requests
- **NSS Module**: Name Service Switch integration for user/group lookups
- **PAM Module**: Pluggable Authentication Module for system authentication
- **SSH Module**: Authorized keys handler for SSH authentication
- **Sudo Configuration**: Group-based sudo access control

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/warp-portal.git
cd warp-portal/cli

# Build the CLI
make build

# Install to system
make install
```

### Download Binary

Download the appropriate binary for your platform from the releases page and install it:

```bash
# Linux x86_64 (optimized static binary for Debian/Ubuntu)
curl -L -o warpportal https://github.com/your-org/warp-portal/releases/download/v1.0.0/warpportal-debian-amd64
chmod +x warpportal
sudo mv warpportal /usr/local/bin/

# Linux x86_64 (standard dynamic binary)
curl -L -o warpportal https://github.com/your-org/warp-portal/releases/download/v1.0.0/warpportal-linux-amd64
chmod +x warpportal
sudo mv warpportal /usr/local/bin/

# macOS (Apple Silicon)
curl -L -o warpportal https://github.com/your-org/warp-portal/releases/download/v1.0.0/warpportal-darwin-arm64
chmod +x warpportal
sudo mv warpportal /usr/local/bin/
```

## Usage

### Install Warp Portal System

Install all components with automatic dependency handling:

```bash
sudo warpportal install
```

Options:
- `--repo URL`: Specify custom repository URL
- `--branch NAME`: Use specific git branch
- `--force`: Force installation over existing components
- `--dry-run`: Show what would be done without executing
- `--verbose`: Show detailed output

### Generate Registration Code

Generate a registration code for your machine:

```bash
warpportal register
```

This will generate a CSV registration code containing:
- Hostname
- Public IP address
- **SSH host key fingerprint** (the same fingerprint that appears in SSH known_hosts files)

The SSH host key fingerprint is extracted from your system's SSH daemon host keys, ensuring it matches exactly what SSH clients see when connecting to your server.

Options:
- `--details`: Show detailed system information
- `--verbose`: Show collection process
- `--dry-run`: Test without generating real data

### Check System Status

Display comprehensive system status:

```bash
warpportal status
```

Options:
- `--json`: Output in JSON format
- `--quiet`: Only show overall status
- `--watch`: Continuously monitor status
- `--detail`: Show detailed information

### Uninstall System

Remove all Warp Portal components:

```bash
sudo warpportal uninstall
```

Options:
- `--keep-config`: Preserve configuration files
- `--keep-logs`: Preserve log files
- `--dry-run`: Show what would be removed
- `--verbose`: Show detailed output

## Configuration

The CLI can be configured using:

1. **Command-line flags**: `--flag value`
2. **Environment variables**: `PORTAL_*`
3. **Configuration file**: `~/.portal.yaml`

### Configuration File Example

```yaml
# ~/.portal.yaml
verbose: true

# Installation settings
install:
  repo: "https://github.com/your-org/warp-portal.git"
  branch: "main"
  force: false
```

## Commands Reference

### Global Flags

- `--config FILE`: Configuration file path
- `--verbose, -v`: Verbose output
- `--dry-run`: Show actions without executing
- `--help`: Show help information

### warpportal install

Install all Warp Portal system components.

**Usage**: `sudo warpportal install [flags]`

**What it does**:
1. Clones the Warp Portal repository
2. Builds all components using Make
3. Installs system libraries and binaries
4. Creates automatic backups of system files
5. Configures system components (NSS, systemd, etc.)
6. Sets up groups and permissions
7. Verifies installation
8. Cleans up temporary files

**Flags**:
- `--repo URL`: Git repository URL (default: auto-detected)
- `--branch NAME`: Git branch to use (default: "main")
- `--force`: Overwrite existing installation

### warpportal register

Generate a machine registration code for manual registration.

**Usage**: `warpportal register [flags]`

**What it does**:
1. Collects system information (hostname, public IP, SSH host key fingerprint)
2. Generates a unique CSV registration code
3. Displays registration instructions and website URL
4. Provides next steps for completing registration

The machine fingerprint is derived from your system's SSH host key fingerprint - the same one that appears in SSH client known_hosts files. This ensures consistent identification across SSH connections and registration.

**Flags**:
- `--details`: Show detailed system information breakdown

### warpportal status

Show comprehensive system status.

**Usage**: `warpportal status [flags]`

**Information displayed**:
- Overall system health
- Installation status of all components
- Service status (daemon, socket)
- Registration status with backend
- Component configuration status
- System connectivity

**Flags**:
- `--json`: JSON output format
- `--quiet`: Minimal output
- `--watch`: Continuous monitoring
- `--detail`: Extended information

### warpportal uninstall

Remove all system components.

**Usage**: `sudo warpportal uninstall [flags]`

**What it does**:
1. Stops running services
2. Removes installed binaries and libraries
3. Restores system configuration backups
4. Removes systemd service files
5. Cleans up logs and temporary files
6. Optionally preserves configuration

**Flags**:
- `--keep-config`: Preserve configuration files
- `--keep-logs`: Preserve log files

## Examples

### Complete Setup Workflow

```bash
# 1. Install the system
sudo warpportal install --verbose

# 2. Generate registration code
warpportal register --details

# 3. Complete registration at website (using the generated code)
# Visit https://portal.warpdev.com/register and paste your code

# 4. Start the daemon
sudo systemctl start warp_portal_daemon
sudo systemctl enable warp_portal_daemon

# 5. Check status
warpportal status --detail

# 6. Monitor continuously
warpportal status --watch
```

### SSH Host Key Fingerprint

The registration system uses your SSH daemon's host key fingerprint as the machine identifier. This ensures:

- **Consistency**: Same fingerprint that SSH clients see in known_hosts
- **Uniqueness**: Each machine has a unique SSH host key
- **Verification**: Admins can verify machine identity using standard SSH tools

To manually verify your SSH host key fingerprint:

```bash
# Method 1: Using ssh-keygen on host keys
sudo ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# Method 2: Using ssh-keyscan (what clients see)
ssh-keyscan -t rsa,ed25519,ecdsa localhost 2>/dev/null | ssh-keygen -lf -

# Method 3: Check your own known_hosts
ssh-keygen -lf ~/.ssh/known_hosts
```

### Troubleshooting

```bash
# Check detailed status
warpportal status --detail --verbose

# Verify installation
sudo warpportal install --dry-run --verbose

# Test with dry run
sudo warpportal uninstall --dry-run --verbose

# Check logs
sudo journalctl -u warp_portal_daemon -f
tail -f /var/log/warp_portal_daemon.log
```

### CI/CD Integration

```bash
# Automated installation
sudo warpportal install --force --repo https://github.com/company/warp-portal.git

# JSON status for monitoring
warpportal status --json | jq '.overall'

# Health check
if warpportal status --quiet | grep -q "healthy"; then
  echo "System is healthy"
else
  echo "System needs attention"
  exit 1
fi
```

## Development

### Building

```bash
# Build for development
make build

# Build for all platforms (including Debian static binaries)
make build-all

# Build specifically for Debian/Ubuntu deployment
make build-debian

# Build for release (optimized)
make build-release

# Create distribution packages
make package
```

### Testing

```bash
# Run tests
make test

# Test specific commands
make run-status
sudo make run-install
make run-register
sudo make run-uninstall
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Install dev dependencies
make deps-dev
```

## Platform Support

### Pre-built Binaries

The CLI is available for multiple platforms:

- **Linux AMD64**: Standard dynamic binary
- **Linux ARM64**: Standard dynamic binary  
- **Linux 386**: 32-bit systems
- **Debian AMD64**: Static binary (no dependencies)
- **Debian ARM64**: Static binary (no dependencies)
- **macOS AMD64**: Intel Macs
- **macOS ARM64**: Apple Silicon Macs

### Debian/Ubuntu Deployment

For Debian and Ubuntu systems, use the static binaries for maximum compatibility:

```bash
# Download and deploy static binary
curl -L -o warpportal https://github.com/your-org/warp-portal/releases/download/v1.0.0/warpportal-debian-amd64
chmod +x warpportal
sudo mv warpportal /usr/local/bin/

# Verify it works
warpportal --version
```

The static binaries have no external dependencies and work on any Debian/Ubuntu system.

## Exit Codes

- `0`: Success
- `1`: General error
- `2`: Invalid command usage
- `3`: Permission denied (need sudo)
- `4`: Component not found/installed
- `5`: Network/connectivity error
- `6`: Configuration error

## Support

For support and documentation:

- **Issues**: https://github.com/your-org/warp-portal/issues
- **Documentation**: https://docs.your-org.com/warp-portal
- **Support**: support@your-org.com

## License

Licensed under the MIT License. See LICENSE file for details.