# Warp Portal Group-Based Sudo Configuration

A group-based sudo configuration system that integrates with the Warp Portal daemon to provide centralized sudo authorization management. This system uses standard Unix groups (`warp-portal-admin` and `warp-portal-user`) and automatically assigns users to the admin group based on the centralized configuration.

## Overview

The Warp Portal group-based sudo system provides:

- **Centralized Authorization**: Users and permissions managed in single YAML configuration
- **Standard Unix Groups**: Uses `warp-portal-admin` and `warp-portal-user` groups
- **Automatic Group Assignment**: Daemon automatically assigns sudoers users to admin group
- **Simple sudo Configuration**: Standard `%warp-portal-admin ALL=(ALL:ALL) ALL` in sudoers
- **Simple Integration**: Uses standard NSS integration with straightforward group-based access

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   sudo command  │───▶│ Standard sudoers│───▶│ warp-portal-    │
│                 │    │ %warp-portal-   │    │ admin group     │
└─────────────────┘    │ admin rule      │    └─────────────────┘
                       └─────────────────┘            │
                              │                       │
                              ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ NSS lookup      │───▶│ Warp Portal     │
                       │ (getgrouplist)  │    │ Daemon          │
                       └─────────────────┘    │ (InitGroups)    │
                              │               └─────────────────┘
                              ▼                       │
                       ┌─────────────────┐            ▼
                       │ User Groups     │    ┌─────────────────┐
                       │ Including       │    │ config.yaml     │
                       │ warp-portal-    │    │ (sudoers list)  │
                       │ admin (if user  │    └─────────────────┘
                       │ in sudoers)     │
                       └─────────────────┘
```

## How It Works

### Group-Based Authorization
1. **System Groups**: Two groups are created: `warp-portal-admin` (for sudo access) and `warp-portal-user` (for regular access)
2. **Sudoers Configuration**: Standard sudoers rule: `%warp-portal-admin ALL=(ALL:ALL) ALL`
3. **Dynamic Group Assignment**: Warp Portal daemon automatically adds users from the `sudoers` configuration list to the `warp-portal-admin` group
4. **NSS Integration**: When sudo performs group lookups, the daemon returns the appropriate groups including `warp-portal-admin` for authorized users

### Configuration Flow
1. Admin defines users in `/etc/warp_portal/config.yaml` sudoers list
2. Daemon reads configuration and identifies sudoers users
3. When NSS performs group lookup for a user, daemon checks if user is in sudoers list
4. If yes, daemon includes `warp-portal-admin` group in the user's group list
5. Sudo sees user is in `warp-portal-admin` group and grants access

## Prerequisites

### System Requirements
- Linux system with NSS support
- Warp Portal daemon running
- Root privileges for installation

### Dependencies

No additional dependencies required. The system uses standard Unix tools and sudo configuration.

## Installation

### 1. Set Up Groups and Sudoers
```bash
cd /path/to/warp-portal/sudo
sudo make install
```

This will:
- Create `warp-portal-admin` and `warp-portal-user` groups with system-assigned GIDs
- Add `%warp-portal-admin ALL=(ALL:ALL) ALL` to sudoers
- Set up logging directory

### 2. Verify Installation
```bash
# Check groups were created with system-assigned GIDs
getent group warp-portal-admin
getent group warp-portal-user

# Check sudoers configuration
sudo grep warp-portal-admin /etc/sudoers

# Show complete group configuration
make show-groups

# Test daemon connectivity
make setup
```

## Configuration

### Daemon Configuration
Ensure the warp-portal daemon is properly configured with users in the `sudoers` section and the special groups defined in `/etc/warp_portal/config.yaml`:

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
- `warp-portal-admin` and `warp-portal-user` groups are created by the installation process
- GIDs are automatically assigned by the system to avoid conflicts
- Users in the `sudoers` list automatically get the `warp-portal-admin` group via daemon
- No hardcoded GIDs - system assigns available IDs during group creation

### Manual Group Management
You can also manually add users to groups if needed:

```bash
# Add user to admin group (for sudo access)
sudo usermod -a -G warp-portal-admin username

# Add user to regular group
sudo usermod -a -G warp-portal-user username

# Remove user from group
sudo gpasswd -d username warp-portal-admin
```

## Usage

### Basic Usage
Once configured, sudo works normally for users in the sudoers list:

```bash
# Regular sudo command (works for users in sudoers list)
sudo ls /root

# Sudo with target user
sudo -u alice whoami

# List privileges - shows warp-portal-admin group membership
sudo -l

# Check user's groups
groups username
```

### Verification Commands
```bash
# Check if user is in warp-portal-admin group
groups username | grep warp-portal-admin

# Test sudo access
sudo -l

# Check daemon logs
tail -f /var/log/warp_portal.log
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
tail -f /var/log/warp_portal_daemon.log

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
getent group warp-portal-admin
getent group warp-portal-user

# Show current group status
make show-groups

# Create groups with system-assigned GIDs
sudo make setup-groups

# Manual creation (if needed)
sudo groupadd warp-portal-admin
sudo groupadd warp-portal-user
```

#### Sudoers Configuration Missing
```bash
# Check sudoers file
sudo grep warp-portal-admin /etc/sudoers

# Manually add if missing
echo '%warp-portal-admin ALL=(ALL:ALL) ALL' | sudo tee -a /etc/sudoers
```

#### Daemon Not Returning Groups
```bash
# Check daemon is running
systemctl status warp-portal-daemon

# Check daemon logs
tail -f /var/log/warp_portal_daemon.log

# Test NSS integration
getent initgroups username

# Check configuration
cat /etc/warp_portal/config.yaml
```

#### User Not Getting Admin Group
```bash
# Verify user is in sudoers config
grep -A5 "sudoers:" /etc/warp_portal/config.yaml

# Test daemon group lookup
getent initgroups username

# Check for errors in daemon logs
grep ERROR /var/log/warp_portal_daemon.log
```

### Log Analysis

#### Daemon Logs
```bash
# Check group assignment logs
grep "Added warp-portal-admin group" /var/log/warp_portal_daemon.log

# Check for warnings
grep "Warning" /var/log/warp_portal_daemon.log

# Monitor real-time
tail -f /var/log/warp_portal_daemon.log
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
# Remove sudoers entry
sudo sed -i '/warp-portal-admin/d' /etc/sudoers

# Remove groups
sudo groupdel warp-portal-admin
sudo groupdel warp-portal-user

# Restart daemon
sudo systemctl restart warp-portal-daemon
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
tail -f /var/log/warp_portal_daemon.log
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
- Users must exist in both Warp Portal config AND be in sudoers list
- Group membership is determined dynamically
- No persistent group membership outside of configuration

## Maintenance

### Log Rotation
Configure logrotate for daemon logs:

```bash
# Create /etc/logrotate.d/warp-portal
cat > /etc/logrotate.d/warp-portal << 'EOF'
/var/log/warp_portal*.log {
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
cd /path/to/warp-portal/sudo
git pull
sudo make install  # Updates any new group or sudoers configuration
```

### Monitoring
Monitor group assignments:

```bash
# Check recent group assignments
grep "Added warp-portal-admin group" /var/log/warp_portal_daemon.log | tail -10

# Monitor sudo usage
grep warp-portal-admin /var/log/auth.log

# Check daemon health
systemctl status warp-portal-daemon
```

## System Integration

### Advantages of This Approach
- **Simpler**: Uses standard Unix groups and sudoers
- **More Compatible**: Works with all sudo versions
- **Easier to Debug**: Standard tools for group membership
- **Less Complex**: No custom components to maintain
- **Better Integration**: Works with existing sudo audit tools
- **Dynamic GIDs**: System assigns GIDs automatically, avoiding conflicts

### Migration from Other Systems
If migrating from other sudo management systems:

```bash
# Install group-based system
sudo make install

# Update daemon configuration with group definitions
# Restart daemon to pick up changes
sudo systemctl restart warp-portal-daemon
```

## Support

### Getting Help
- Check daemon logs: `tail -f /var/log/warp_portal_daemon.log`
- Verify daemon status: `systemctl status warp-portal-daemon`
- Test group membership: `getent initgroups username`
- Check configuration: `cat /etc/warp_portal/config.yaml`

### Reporting Issues
When reporting issues, include:
- Operating system and version
- Daemon version and logs
- Configuration files (sanitized)
- Output of `getent group warp-portal-admin`
- Steps to reproduce

## License

This system is part of the Warp Portal project. See project documentation for licensing details.