# Sudo Socket Plugin

A custom sudo plugin that integrates with the Sudo Socket daemon to provide centralized sudo authorization management. This plugin communicates with the warp-portal daemon via Unix socket to determine if users have sudo privileges based on the centralized configuration.

## Overview

The Sudo Socket sudo plugin provides:

- **Centralized Authorization**: Users and permissions managed in single YAML configuration
- **Real-time Communication**: Direct socket communication with warp-portal daemon
- **Comprehensive Logging**: Detailed audit trail of sudo attempts and decisions
- **Fallback Safety**: Graceful handling when daemon is unavailable
- **Standard Integration**: Uses official sudo plugin API for seamless integration

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   sudo command  │───▶│ Sudo Plugin API │───▶│ Sudo Socket     │
│                 │    │ (this plugin)   │    │ Daemon          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                       │
                              ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ Plugin Logs     │    │ config.yaml     │
                       │ /var/log/       │    │ (sudoers list)  │
                       │ warp_portal_    │    └─────────────────┘
                       │ sudo.log        │
                       └─────────────────┘
```

## Features

### Policy Enforcement
- Checks user authorization against centralized sudoers list
- Supports target user specification
- Command-aware authorization (future enhancement)
- Real-time policy updates (no cache invalidation needed)

### Logging and Auditing
- Comprehensive logging to `/var/log/sudo_socket.log`
- Syslog integration for system administrators
- Debug logging for troubleshooting
- Structured log format with timestamps and context

### Plugin Functions
- `policy_check_policy`: Main authorization function
- `policy_list`: Show user privileges
- `policy_validate`: Credential validation
- `policy_open/close`: Plugin lifecycle management
- `policy_show_version`: Version and configuration display

## Prerequisites

### System Requirements
- Linux system with sudo 1.8+ that supports plugins
- Access to sudo development headers (`sudo-dev` or `sudo-devel`)
- Running warp-portal daemon
- Root privileges for installation

### Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install sudo-dev build-essential
```

**RHEL/CentOS/Fedora:**
```bash
# RHEL/CentOS
sudo yum install sudo-devel gcc make

# Fedora
sudo dnf install sudo-devel gcc make
```

**Arch Linux:**
```bash
sudo pacman -S sudo base-devel
```

## Installation

### 1. Clone and Build
```bash
cd /path/to/warp-portal/sudo
make all
```

### 2. Install Plugin
```bash
sudo make install
```

This will:
- Install plugin to `/usr/libexec/sudo/sudo_socket.so`
- Create configuration file at `/etc/sudo.conf.d/sudo_socket.conf`
- Set up log file at `/var/log/sudo_socket.log`
- Configure appropriate permissions

### 3. Verify Installation
```bash
# Check plugin loaded correctly
sudo -V

# Test daemon connectivity
make test

# Check configuration
make check-config
```

## Configuration

### Plugin Configuration

#### Method 1: Direct sudo.conf Configuration (Recommended)
On many systems, the `sudo.conf.d` directory is not supported. In this case, you must edit the main `/etc/sudo.conf` file directly:

```bash
# Create or edit /etc/sudo.conf
sudo nano /etc/sudo.conf

# Add the following line:
Plugin policy /usr/libexec/sudo/sudo_socket.so
```

**Important Notes:**
- If `/etc/sudo.conf` doesn't exist, create it with the above content
- If it exists, add the plugin line to the existing configuration
- Ensure the plugin line comes before any other policy plugins
- Test with `sudo -V` to verify the plugin loads correctly

#### Method 2: Using sudo.conf.d (If Supported)
Some systems support configuration in `/etc/sudo.conf.d/`. The installation creates `/etc/sudo.conf.d/sudo_socket.conf` with:

```
# Sudo Socket Plugin Configuration
Plugin policy /usr/libexec/sudo/sudo_socket.so
```

**To verify sudo.conf.d support:**
```bash
# Check if your sudo version supports .conf.d
sudo -V | grep -i conf
ls -la /etc/sudo.conf.d/
```

If the directory doesn't exist or sudo doesn't load plugins from it, use Method 1.

### Daemon Configuration
Ensure the warp-portal daemon is properly configured with users in the `sudoers` section of `/etc/warp_portal/config.yaml`:

```yaml
sudoers:
  - admin
  - miguel
  - alice

users:
  miguel:
    uid: 2000
    gid: 2000
    gecos: "Miguel Campos"
    dir: "/home/miguel"
    shell: "/bin/bash"
    # ... other user attributes
```

### Multiple Plugin Configuration
If you need to use this alongside other sudo plugins, configure in `/etc/sudo.conf`:

```
# Main sudo configuration
Plugin policy /usr/libexec/sudo/sudo_socket.so
Plugin audit   /usr/libexec/sudo/sudoers.so audit
Plugin io      /usr/libexec/sudo/sudoers.so io
```

## Usage

### Basic Usage
Once installed and configured, sudo commands work normally:

```bash
# Regular sudo command
sudo ls /root

# Sudo with target user
sudo -u alice whoami

# List privileges
sudo -l

# Validate credentials
sudo -v
```

### Plugin-Specific Information
```bash
# Show plugin version and configuration
sudo -V

# Check plugin loading in verbose mode
sudo -V | grep -i warp
```

## Testing

### Basic Tests
```bash
# Run plugin tests
make test

# Check daemon connectivity
make setup

# View configuration status
make check-config
```

### Manual Testing
```bash
# Test with logging
sudo ls /root

# Check logs
tail -f /var/log/sudo_socket.log

# Test authorization denial (user not in sudoers list)
# (Log in as non-privileged user)
sudo ls /root  # Should be denied
```

### Debug Mode
Build and test with debug output:

```bash
make debug
sudo make install
# Debug information will appear in logs
```

## Troubleshooting

### Common Issues

#### Plugin Not Loading
```bash
# Check if plugin file exists
ls -la /usr/libexec/sudo/sudo_socket.so

# Verify configuration method being used
# Method 1: Check main sudo.conf
cat /etc/sudo.conf

# Method 2: Check sudo.conf.d (if supported)
cat /etc/sudo.conf.d/sudo_socket.conf

# Check sudo can find and load the plugin
sudo -V | grep -i plugin

# If plugin isn't loading, ensure you're using the correct configuration method:
# - Most systems require direct /etc/sudo.conf editing
# - Only some newer systems support /etc/sudo.conf.d/
```

#### Configuration Method Issues
```bash
# If using sudo.conf.d doesn't work, switch to direct configuration:
sudo echo "Plugin policy /usr/libexec/sudo/sudo_socket.so" >> /etc/sudo.conf

# Remove the .conf.d file to avoid conflicts:
sudo rm -f /etc/sudo.conf.d/sudo_socket.conf

# Test the configuration:
sudo -V | grep -i "sudo_socket\|plugin"
```

#### Daemon Connection Issues
```bash
# Check daemon is running
systemctl status warp-portal-daemon

# Verify socket exists
ls -la /run/warp_portal.sock

# Test socket connectivity
echo '{"op":"checksudo","username":"testuser"}' | socat - UNIX-CONNECT:/run/warp_portal.sock
```

#### Permission Issues
```bash
# Check log file permissions
ls -la /var/log/sudo_socket.log

# Fix log permissions if needed
sudo chmod 640 /var/log/sudo_socket.log
sudo chown root:adm /var/log/sudo_socket.log
```

### Log Analysis

#### Log Levels
- **INFO**: Normal operations and successful authorizations
- **WARN**: Authorization denials and recoverable errors
- **ERROR**: Connection failures and critical errors
- **DEBUG**: Detailed operation traces (debug build only)

#### Example Log Entries
```
[2024-01-15 10:30:45] INFO: Sudo Socket sudo plugin initialized (version 1.13)
[2024-01-15 10:30:50] INFO: Policy check for user miguel, command: ls /root
[2024-01-15 10:30:50] INFO: Authorization granted for user miguel to run ls /root as root
[2024-01-15 10:31:15] WARN: Authorization denied for user bob to run whoami as root (response: DENY)
[2024-01-15 10:31:20] ERROR: Failed to connect to daemon socket: Connection refused
```

### Recovery Procedures

#### Plugin Malfunction
If the plugin causes issues:

```bash
# Temporarily disable the plugin
sudo mv /etc/sudo.conf.d/sudo_socket.conf /etc/sudo.conf.d/sudo_socket.conf.disabled

# Or uninstall completely
cd /path/to/warp-portal/sudo
sudo make uninstall
```

#### Emergency Access
Always keep a root shell open during testing. If locked out:

1. Boot into recovery mode
2. Remove plugin configuration
3. Restart system
4. Debug issues before reinstalling

## Development

### Building from Source
```bash
# Debug build with extra logging
make debug

# Show build information
make info

# Clean build artifacts
make clean
```

### Plugin Development
The plugin implements the standard sudo plugin API:

- Policy Plugin Interface
- Socket communication protocol
- Error handling and logging
- Plugin lifecycle management

Key files:
- `sudo_socket.c` - Main plugin implementation
- `Makefile` - Build and installation automation
- `README.md` - This documentation

### Protocol Details
Communication with daemon uses JSON over Unix socket:

**Request Format:**
```json
{
  "op": "checksudo",
  "username": "miguel",
  "target_user": "root",
  "command": "ls /root"
}
```

**Response Format:**
```
ALLOW
```
or
```
DENY
```

## Security Considerations

### Plugin Security
- Plugin runs with root privileges
- Validates all daemon responses
- Fails securely when daemon unavailable
- Comprehensive audit logging

### Daemon Communication
- Unix socket communication (local only)
- No network exposure
- JSON protocol with input validation
- Graceful handling of daemon failures

### Configuration Security
- Plugin configuration requires root access
- Log files protected with appropriate permissions
- No credential caching or persistence

## Maintenance

### Log Rotation
Configure logrotate for plugin logs:

```bash
# Create /etc/logrotate.d/warp-portal-sudo
cat > /etc/logrotate.d/warp-portal-sudo << 'EOF'
/var/log/sudo_socket.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
```

### Updates
To update the plugin:

```bash
cd /path/to/warp-portal/sudo
git pull
make clean
make all
sudo make install
```

### Monitoring
Monitor plugin health:

```bash
# Check recent authorization decisions
tail -100 /var/log/sudo_socket.log | grep -E "(ALLOW|DENY)"

# Monitor daemon connectivity
grep "connect to daemon" /var/log/sudo_socket.log

# Plugin loading status
sudo -V | grep -i warp
```

## Support

### Getting Help
- Check logs first: `tail -f /var/log/sudo_socket.log`
- Verify daemon status: `systemctl status warp-portal-daemon`
- Test plugin loading: `sudo -V`
- Review configuration: `make check-config`

### Reporting Issues
When reporting issues, include:
- Operating system and version
- Sudo version (`sudo -V`)
- Plugin logs (sanitized)
- Daemon logs
- Configuration files
- Steps to reproduce

## License

This plugin is part of the Sudo Socket project. See project documentation for licensing details.