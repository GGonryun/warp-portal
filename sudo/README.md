# P0 Agent Group-Based Sudo Configuration

A group-based sudo configuration system that integrates with the P0 Agent daemon to provide centralized sudo authorization management. This system uses standard Unix groups (`p0-agent-admin` and `p0-agent-user`) and automatically assigns users to the admin group based on the centralized configuration.

## Overview

The P0 Agent group-based sudo system provides:

- **Centralized Authorization**: Users and permissions managed in single YAML configuration
- **Standard Unix Groups**: Uses `p0-agent-admin` and `p0-agent-user` groups
- **Automatic Group Assignment**: Daemon automatically assigns sudoers users to admin group
- **Simple sudo Configuration**: Standard `%p0-agent-admin ALL=(ALL:ALL) ALL` in sudoers
- **Simple Integration**: Uses standard NSS integration with straightforward group-based access

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   sudo command  │───▶│ Standard sudoers│───▶│ p0-agent-    │
│                 │    │ %p0-agent-   │    │ admin group     │
└─────────────────┘    │ admin rule      │    └─────────────────┘
                       └─────────────────┘            │
                              │                       │
                              ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ NSS lookup      │───▶│ P0 Agent     │
                       │ (getgrouplist)  │    │ Daemon          │
                       └─────────────────┘    │ (InitGroups)    │
                              │               └─────────────────┘
                              ▼                       │
                       ┌─────────────────┐            ▼
                       │ User Groups     │    ┌─────────────────┐
                       │ Including       │    │ config.yaml     │
                       │ p0-agent-    │    │ (sudoers list)  │
                       │ admin (if user  │    └─────────────────┘
                       │ in sudoers)     │
                       └─────────────────┘
```

## How It Works

### Group-Based Authorization
1. **System Groups**: Two groups are created: `p0-agent-admin` (for sudo access) and `p0-agent-user` (for regular access)
2. **Sudoers Configuration**: Standard sudoers rule: `%p0-agent-admin ALL=(ALL:ALL) ALL`
3. **Dynamic Group Assignment**: P0 Agent daemon automatically adds users from the `sudoers` configuration list to the `p0-agent-admin` group
4. **NSS Integration**: When sudo performs group lookups, the daemon returns the appropriate groups including `p0-agent-admin` for authorized users

### Configuration Flow
1. Admin defines users in `/etc/p0_agent/config.yaml` sudoers list
2. Daemon reads configuration and identifies sudoers users
3. When NSS performs group lookup for a user, daemon checks if user is in sudoers list
4. If yes, daemon includes `p0-agent-admin` group in the user's group list
5. Sudo sees user is in `p0-agent-admin` group and grants access

## Prerequisites

### System Requirements
- Linux system with NSS support
- P0 Agent daemon running
- Root privileges for installation

### Dependencies

No additional dependencies required. The system uses standard Unix tools and sudo configuration.

## Installation

### 1. Set Up Groups and Sudoers
```bash
cd /path/to/p0-agent/sudo
sudo make install
```

This will:
- Create `p0-agent-admin` group (GID 64200) and `p0-agent-user` group (GID 64201)
- Backup existing sudoers file with timestamp
- Add `%p0-agent-admin ALL=(ALL:ALL) ALL` to `/etc/sudoers.d/p0-agent`
- Set up logging directory

### 2. Verify Installation
```bash
# Check groups were created with reserved GIDs
getent group p0-agent-admin  # Should show GID 64200
getent group p0-agent-user   # Should show GID 64201

# Check sudoers configuration
sudo cat /etc/sudoers.d/p0-agent

# Show complete group configuration
make show-groups

# Test daemon connectivity
make setup
```

## Configuration

### Daemon Configuration
Ensure the p0-agent daemon is properly configured with users in the `sudoers` section and the special groups defined in `/etc/p0_agent/config.yaml`:

```yaml
sudoers:
  - admin
  - miguel

users:
  miguel:
    uid: 2000
    gid: 2000
    gecos: "Miguel Campos"
    dir: "/home/miguel"
    shell: "/bin/bash"
    # ... other user attributes
  
  admin:
    uid: 1000
    gid: 1000
    gecos: "Administrator"
    dir: "/home/admin"
    shell: "/bin/bash"
  
  alice:
    uid: 2001
    gid: 2001
    gecos: "Alice Smith"
    dir: "/home/alice"
    shell: "/bin/bash"

groups:
  # Regular user groups
  miguel:
    gid: 2000
    members:
      - miguel
  
  admin:
    gid: 1000
    members:
      - admin
  
  alice:
    gid: 2001
    members:
      - alice
  
```

**Important Notes:**
- `p0-agent-admin` (GID 64200) and `p0-agent-user` (GID 64201) groups are created by the installation process
- Reserved GIDs are used to ensure consistency across systems
- Users in the `sudoers` list automatically get the `p0-agent-admin` group via daemon
- Reserved GIDs 64200-64201 are used to avoid conflicts with system-assigned IDs

### Manual Group Management
You can also manually add users to groups if needed:

```bash
# Add user to admin group (for sudo access)
sudo usermod -a -G p0-agent-admin username

# Add user to regular group
sudo usermod -a -G p0-agent-user username

# Remove user from group
sudo gpasswd -d username p0-agent-admin
```

## Usage

### Basic Usage
Once configured, sudo works normally for users in the sudoers list:

```bash
# Regular sudo command (works for users in sudoers list)
sudo ls /root

# Sudo with target user
sudo -u alice whoami

# List privileges - shows p0-agent-admin group membership
sudo -l

# Check user's groups
groups username
```

### Verification Commands
```bash
# Check if user is in p0-agent-admin group
groups username | grep p0-agent-admin

# Test sudo access
sudo -l

# Check daemon logs
tail -f /var/log/p0_agent.log
```

## Testing

### Basic Tests
```bash
# Test group creation and sudoers configuration
make setup

# Test with a sudoers user
# (Log in as a user listed in the sudoers config)
sudo whoami  # Should work and return 'root'

# Test with a non-sudoers user
# (Log in as a user NOT in the sudoers config)
sudo whoami  # Should be denied
```

### Manual Testing
```bash
# Test group membership via NSS
getent initgroups username

# Check daemon response
tail -f /var/log/p0_agent_daemon.log

# Test different users
for user in admin miguel alice; do
  echo "Testing user: $user"
  sudo -u $user sudo -l
done
```

## Troubleshooting

### Common Issues

#### Groups Not Created
```bash
# Check if groups exist
getent group p0-agent-admin
getent group p0-agent-user

# Show current group status
make show-groups

# Create groups with reserved GIDs (64200-64201)
sudo make setup-groups

# Manual creation (if needed) - use reserved GIDs
sudo groupadd --gid 64200 p0-agent-admin
sudo groupadd --gid 64201 p0-agent-user
```

#### Sudoers Configuration Missing
```bash
# Check sudoers configuration
sudo cat /etc/sudoers.d/p0-agent

# Manually add if missing (recommended approach)
echo '%p0-agent-admin ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/p0-agent
sudo chmod 440 /etc/sudoers.d/p0-agent
```

#### Daemon Not Returning Groups
```bash
# Check daemon is running
systemctl status p0-agent-daemon

# Check daemon logs
tail -f /var/log/p0_agent_daemon.log

# Test NSS integration
getent initgroups username

# Check configuration
cat /etc/p0_agent/config.yaml
```

#### User Not Getting Admin Group
```bash
# Verify user is in sudoers config
grep -A5 "sudoers:" /etc/p0_agent/config.yaml

# Test daemon group lookup
getent initgroups username

# Check for errors in daemon logs
grep ERROR /var/log/p0_agent_daemon.log
```

### Log Analysis

#### Daemon Logs
```bash
# Check group assignment logs
grep "Added p0-agent-admin group" /var/log/p0_agent_daemon.log

# Check for warnings
grep "Warning" /var/log/p0_agent_daemon.log

# Monitor real-time
tail -f /var/log/p0_agent_daemon.log
```

### Recovery Procedures

#### Reset Group Configuration
```bash
# Uninstall current setup
sudo make uninstall

# Clean reinstall
sudo make install

# Verify
make setup
```

#### Manual Cleanup
```bash
# Remove sudoers configuration (safer approach)
sudo rm -f /etc/sudoers.d/p0-agent

# Remove groups (will preserve GID assignments for future use)
sudo groupdel p0-agent-admin
sudo groupdel p0-agent-user

# Restart daemon
sudo systemctl restart p0-agent-daemon
```

## Development

### Testing Changes
```bash
# Test group setup
make install

# Verify configuration
make setup

# Show group configuration details
make show-groups

# Check logs
tail -f /var/log/p0_agent_daemon.log
```

### Key Components
- **Makefile**: Automates group creation and sudoers configuration
- **Daemon Integration**: Modified `InitGroups` function automatically assigns group membership
- **NSS Module**: Existing NSS integration handles group lookups

## Security Considerations

### Group Security
- Groups are managed by standard Unix permissions
- Only root can modify group membership
- Daemon runs with appropriate privileges to perform group lookups
- No additional attack surface compared to standard sudoers

### Configuration Security
- Configuration requires root access to modify
- Daemon validates all group lookups
- Standard sudoers syntax validation
- Comprehensive audit logging

### Access Control
- Users must exist in both P0 Agent config AND be in sudoers list
- Group membership is determined dynamically
- No persistent group membership outside of configuration

## Maintenance

### Log Rotation
Configure logrotate for daemon logs:

```bash
# Create /etc/logrotate.d/p0-agent
cat > /etc/logrotate.d/p0-agent << 'EOF'
/var/log/p0_agent*.log {
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
To update the configuration:

```bash
cd /path/to/p0-agent/sudo
git pull
sudo make install  # Updates any new group or sudoers configuration
```

### Monitoring
Monitor group assignments:

```bash
# Check recent group assignments
grep "Added p0-agent-admin group" /var/log/p0_agent_daemon.log | tail -10

# Monitor sudo usage
grep p0-agent-admin /var/log/auth.log

# Check daemon health
systemctl status p0-agent-daemon
```

## System Integration

### Advantages of This Approach
- **Simpler**: Uses standard Unix groups and sudoers
- **More Compatible**: Works with all sudo versions
- **Easier to Debug**: Standard tools for group membership
- **Less Complex**: No custom components to maintain
- **Better Integration**: Works with existing sudo audit tools
- **Consistent**: Reserved GIDs ensure consistent behavior across systems
- **Safe**: Uses `/etc/sudoers.d/` with validation and backup mechanisms

### Migration from Other Systems
If migrating from other sudo management systems:

```bash
# Install group-based system
sudo make install

# Update daemon configuration with group definitions
# Restart daemon to pick up changes
sudo systemctl restart p0-agent-daemon
```

## Support

### Getting Help
- Check daemon logs: `tail -f /var/log/p0_agent_daemon.log`
- Verify daemon status: `systemctl status p0-agent-daemon`
- Test group membership: `getent initgroups username`
- Check configuration: `cat /etc/p0_agent/config.yaml`

### Reporting Issues
When reporting issues, include:
- Operating system and version
- Daemon version and logs
- Configuration files (sanitized)
- Output of `getent group p0-agent-admin`
- Steps to reproduce

## License

This system is part of the P0 Agent project. See project documentation for licensing details.