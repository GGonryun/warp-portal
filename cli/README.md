# P0 Agent CLI

A command-line interface for managing the P0 Agent authentication system.

## Overview

The P0 Agent CLI provides a unified interface for installing, configuring, and managing all P0 Agent components including:

- **Daemon**: Core Go service that handles authentication requests
- **NSS Socket Module**: Real-time Name Service Switch integration for user/group lookups
- **NSS Cache Module**: High-performance cached Name Service Switch integration
- **PAM Module**: Pluggable Authentication Module for system authentication
- **SSH Module**: Authorized keys handler for SSH authentication
- **Sudo Configuration**: Group-based sudo access control

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/p0-agent.git
cd p0-agent/cli

# Build the CLI
make build

# Install to system
make install
```

### Download Binary

Download the appropriate binary for your platform from the releases page and install it:

```bash
# Linux x86_64 (optimized static binary for Debian/Ubuntu)
curl -L -o p0agent https://github.com/your-org/p0-agent/releases/download/v1.0.0/p0agent-debian-amd64
chmod +x p0agent
sudo mv p0agent /usr/local/bin/

# Linux x86_64 (standard dynamic binary)
curl -L -o p0agent https://github.com/your-org/p0-agent/releases/download/v1.0.0/p0agent-linux-amd64
chmod +x p0agent
sudo mv p0agent /usr/local/bin/

# macOS (Apple Silicon)
curl -L -o p0agent https://github.com/your-org/p0-agent/releases/download/v1.0.0/p0agent-darwin-arm64
chmod +x p0agent
sudo mv p0agent /usr/local/bin/
```

## Usage

### Install P0 Agent System

Install all components with automatic dependency handling:

```bash
sudo p0agent install
```

Options:

- `--repo URL`: Specify custom repository URL
- `--branch NAME`: Use specific git branch
- `--force`: Force installation over existing components
- `--dry-run`: Show what would be done without executing
- `--verbose`: Show detailed output

### Machine Registration

Register your machine with P0 Agent (requires sudo):

```bash
# Generate base64-encoded registration code
sudo p0agent register
```

**Registration Process**:

- Collects system information (hostname, public IP, SSH host key fingerprint)
- Reads JWK public key from the installation  
- Reads machine labels from the daemon configuration file
- Generates a base64-encoded JSON registration code containing all machine data
- Code must be entered at the registration website for manual approval

Options:

- `--details`: Show detailed system information
- `--verbose`: Show collection process
- `--dry-run`: Test without generating real data

**Note**: Machine labels are read from the `labels` field in `/etc/p0_agent/config.yaml`

### Check System Status

Display comprehensive system status:

```bash
p0agent status
```

Options:

- `--json`: Output in JSON format
- `--quiet`: Only show overall status
- `--watch`: Continuously monitor status
- `--detail`: Show detailed information

### Uninstall System

Remove all P0 Agent components:

```bash
sudo p0agent uninstall
```

Options:

- `--keep-config`: Preserve configuration files
- `--keep-logs`: Preserve log files
- `--dry-run`: Show what would be removed
- `--verbose`: Show detailed output

## Configuration

The CLI can be configured using:

1. **Command-line flags**: `--flag value`
2. **Environment variables**: `P0_AGENT_*`
3. **Configuration file**: `~/.p0-agent.yaml`

### Configuration File Examples

**CLI Configuration (`~/.p0-agent.yaml`)**:
```yaml
verbose: true

# Installation settings
install:
  repo: "https://github.com/your-org/p0-agent.git"
  branch: "main"
  force: false
```

**Daemon Configuration (`/etc/p0_agent/config.yaml`)**:
```yaml
version: "1.0"
provider:
  type: "http"
  environment: "production"
  config:
    url: "https://api.example.com"

# Machine labels for registration
labels:
  - "region=us-west"
  - "env=backend" 
  - "team=security"
```

## Commands Reference

### Global Flags

- `--config FILE`: Configuration file path
- `--verbose, -v`: Verbose output
- `--dry-run`: Show actions without executing
- `--help`: Show help information

### p0agent install

Install all P0 Agent system components.

**Usage**: `sudo p0agent install [flags]`

**What it does**:

1. Clones the P0 Agent repository
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

### p0agent register

Register machine with P0 Agent.

**Usage**: `sudo p0agent register [flags]`

**What it does**:

1. Collects system information (hostname, public IP, SSH host key fingerprint)
2. Reads JWK public key from the installation
3. Generates a base64-encoded JSON registration code
4. Includes environment ID (from daemon config) and optional machine labels

The machine fingerprint is derived from your system's SSH host key fingerprint - the same one that appears in SSH client known_hosts files. This ensures consistent machine identification.

**Flags**:

- `--details`: Show detailed system information breakdown

**Note**: Machine labels are configured in the `labels` field of `/etc/p0_agent/config.yaml`

### p0agent status

Show comprehensive system status.

**Usage**: `p0agent status [flags]`

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

### p0agent uninstall

Remove all system components.

**Usage**: `sudo p0agent uninstall [flags]`

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
sudo p0agent install --verbose

# 2. Generate registration code
sudo p0agent register --details

# 4. Start the daemon
sudo systemctl start p0_agent_daemon
sudo systemctl enable p0_agent_daemon

# 5. Check status
p0agent status --detail

# 6. Monitor continuously
p0agent status --watch
```

### SSH Host Key Fingerprint

The registration system uses your system's SSH host key fingerprint as the machine identifier. This ensures:

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
p0agent status --detail --verbose

# Verify installation
sudo p0agent install --dry-run --verbose

# Test with dry run
sudo p0agent uninstall --dry-run --verbose

# Check logs
sudo journalctl -u p0_agent_daemon -f
tail -f /var/log/p0_agent_daemon.log
```

### CI/CD Integration

```bash
# Automated installation
sudo p0agent install --force --repo https://github.com/company/p0-agent.git

# JSON status for monitoring
p0agent status --json | jq '.overall'

# Health check
if p0agent status --quiet | grep -q "healthy"; then
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
curl -L -o p0agent https://github.com/your-org/p0-agent/releases/download/v1.0.0/p0agent-debian-amd64
chmod +x p0agent
sudo mv p0agent /usr/local/bin/

# Verify it works
p0agent --version
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

- **Issues**: https://github.com/your-org/p0-agent/issues
- **Documentation**: https://docs.your-org.com/p0-agent
- **Support**: support@your-org.com

## License

Licensed under the MIT License. See LICENSE file for details.
