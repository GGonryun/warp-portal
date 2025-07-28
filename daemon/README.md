# Warp Portal Daemon

This is the central authentication daemon that provides user/group data, SSH key management, sudo authorization, and session lifecycle tracking for the Warp Portal authentication system.

## Features

- Unix domain socket server on `/run/warp_portal.sock`
- JSON request/response protocol
- YAML-based configuration with live reloading
- User and group management
- SSH public key management
- Sudo authorization checking
- **Session lifecycle tracking** (NEW)
- Graceful shutdown handling
- Comprehensive logging with audit trails

## Operations Supported

### User Management
- **getpwnam**: Get user information by username
- **getpwuid**: Get user information by UID
- **getpwent**: Enumerate all users

### Group Management
- **getgrnam**: Get group information by group name
- **getgrgid**: Get group information by GID
- **getgrent**: Enumerate all groups
- **initgroups**: Get supplementary group list for a user

### SSH Key Management
- **getkeys**: Retrieve SSH public keys for a user

### Authentication
- **checksudo**: Check if user has sudo privileges

### Session Management (NEW)
- **open_session**: Handle PAM session start events
- **close_session**: Handle PAM session end events
  - Remote host tracking and timestamps
  - Comprehensive audit logging

## Logging Configuration

The daemon supports configurable log levels for controlling verbosity:

- **`error`**: Only critical errors
- **`warn`**: Errors and warnings  
- **`info`**: General information (default)
- **`debug`**: Detailed debugging information

Set the log level in your config file:
```yaml
log_level: debug  # or error, warn, info
```

The log level can be changed at runtime by modifying the config file - the daemon will reload it automatically.

## Configuration Data

The daemon uses `/etc/warp_portal/config.yaml` for configuration:

```yaml
provider:
  type: file

# Logging verbosity: error, warn, info, debug (default: info)
log_level: info

# Users with sudo privileges
sudoers:
  - admin
  - miguel

# System users/groups to automatically deny (performance optimization)
deny_users:
  - mail
  - daemon
  - bin
  - sys
  - sync
  - games
  - man
  - lp
  - news
  - uucp
  - proxy
  - www-data
  - backup
  - list
  - irc
  - gnats
  - nobody
  - systemd-network
  - systemd-resolve
  - messagebus
  - systemd-timesync
  - syslog
  - _apt
  - tss
  - uuidd
  - systemd-oom
  - tcpdump
  - avahi-autoipd
  - usbmux
  - dnsmasq
  - kernoops
  - avahi
  - cups-pk-helper
  - rtkit
  - whoopsie
  - sssd
  - speech-dispatcher
  - nm-openvpn
  - saned
  - colord
  - geoclue
  - pulse
  - gdm
  - debian-exim

deny_groups:
  - mail
  - daemon
  - bin
  - sys
  - adm
  - tty
  - disk
  - lp
  - news
  - uucp
  - man
  - proxy
  - kmem
  - dialout
  - fax
  - voice
  - cdrom
  - floppy
  - tape
  - sudo
  - audio
  - dip
  - www-data
  - backup
  - operator
  - list
  - irc
  - src
  - gnats
  - shadow
  - utmp
  - video
  - sasl
  - plugdev
  - staff
  - games
  - users
  - nogroup
  - systemd-journal
  - systemd-network
  - systemd-resolve
  - crontab
  - messagebus
  - systemd-timesync
  - input
  - sgx
  - kvm
  - render
  - syslog
  - _apt
  - tss
  - bluetooth
  - ssl-cert
  - uuidd
  - systemd-oom
  - tcpdump
  - ssh
  - landscape
  - lxd
  - systemd-coredump
  - avahi-autoipd
  - netdev
  - usbmux

users:
  miguel:
    uid: 2000
    gid: 2000
    gecos: "Miguel Campos"
    dir: "/home/miguel"
    shell: "/bin/bash"
    keys:
      - "ssh-rsa AAAAB3NzaC1yc2E... miguel@example.com"

  admin:
    uid: 1000
    gid: 1000
    gecos: "System Administrator"
    dir: "/root"
    shell: "/bin/bash"
    keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1... admin@server"

groups:
  developers:
    gid: 3000
    members:
      - miguel
      - alice
```

## Configuration

Add the user provisioning section to your config file to enable automatic user management:

```yaml
# User provisioning settings for automatic passwd file management
user_provisioning:
  retain_users: true   # Add users to passwd file when session opens (default: true)
  reclaim_users: false # Remove users from passwd file when session closes (default: true)
```

### Session Logging

The daemon provides comprehensive session logging:
- `[SESSION_START]` - User session initiation
- `[SESSION_END]` - User session termination  
- `[AUDIT]` - Security audit trail with remote host information
- Timestamped entries for session duration analysis
- Remote host tracking for security monitoring

## Building and Running

### Build

```bash
go build -o warp_portal_daemon
```

### Run

```bash
sudo ./warp_portal_daemon
```

The daemon must run as root to create the socket in `/run/` and set appropriate permissions.

### Run in Background

```bash
sudo ./warp_portal_daemon &
```

### Stop

```bash
sudo pkill warp_portal_daemon
```

## Testing

Once the daemon is running, you can test it with the NSS plugin:

```bash
# Test user lookups
getent passwd miguel
getent passwd testuser
id miguel

# Test group lookups
getent group users
getent group sudo
```

## Socket Protocol Reference

The daemon handles the following socket operations via Unix domain socket at `/run/warp_portal.sock`:

### User Management Operations

#### getpwnam (lookup user by name)

Request:
```json
{
  "op": "getpwnam",
  "username": "miguel"
}
```

Response:
```json
{
  "status": "success",
  "user": {
    "name": "miguel",
    "uid": 2000,
    "gid": 2000,
    "gecos": "Miguel Campos",
    "dir": "/home/miguel",
    "shell": "/bin/bash"
  }
}
```

Error Response:
```json
{
  "status": "error",
  "error": "User not found"
}
```

#### getpwuid (lookup user by UID)

Request:
```json
{
  "op": "getpwuid",
  "uid": 2000
}
```

Response: (same format as getpwnam)

#### getpwent (enumerate users)

Request:
```json
{
  "op": "getpwent",
  "index": 0
}
```

Response:
```json
{
  "status": "success",
  "user": {
    "name": "miguel",
    "uid": 2000,
    "gid": 2000,
    "gecos": "Miguel Campos",
    "dir": "/home/miguel",
    "shell": "/bin/bash"
  }
}
```

End of list response:
```json
{
  "status": "end"
}
```

### Group Management Operations

#### getgrnam (lookup group by name)

Request:
```json
{
  "op": "getgrnam",
  "groupname": "developers"
}
```

Response:
```json
{
  "status": "success",
  "group": {
    "name": "developers",
    "gid": 3000,
    "members": ["miguel", "alice", "bob"]
  }
}
```

Error Response:
```json
{
  "status": "error",
  "error": "Group not found"
}
```

#### getgrgid (lookup group by GID)

Request:
```json
{
  "op": "getgrgid",
  "gid": 3000
}
```

Response: (same format as getgrnam)

#### getgrent (enumerate groups)

Request:
```json
{
  "op": "getgrent",
  "index": 0
}
```

Response:
```json
{
  "status": "success",
  "group": {
    "name": "developers",
    "gid": 3000,
    "members": ["miguel", "alice", "bob"]
  }
}
```

End of list response:
```json
{
  "status": "end"
}
```

#### initgroups (get user's supplementary groups)

Request:
```json
{
  "op": "initgroups",
  "username": "miguel"
}
```

Response:
```json
{
  "status": "success",
  "groups": [2000, 3000, 64201, 64200]
}
```

Error Response:
```json
{
  "status": "error",
  "error": "Failed to get user groups"
}
```

### SSH Key Management

#### getkeys (get SSH public keys for user)

Request:
```json
{
  "op": "getkeys",
  "username": "miguel",
  "key_type": "ssh-rsa",
  "key_fingerprint": "SHA256:abc123..."
}
```

Response:
```json
{
  "status": "success",
  "keys": [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vKuIl8X2wXIvGx1Qr... miguel@example.com",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI8H1E5qhL9X2wXIvGx1Q... miguel@laptop"
  ]
}
```

Error Response:
```json
{
  "status": "error",
  "error": "No SSH keys found"
}
```

### Authentication Operations

#### checksudo (check sudo privileges)

Request:
```json
{
  "op": "checksudo",
  "username": "miguel"
}
```

Response: (plain text, not JSON)
```
ALLOW
```

Or:
```
DENY
```

### Session Management Operations

#### open_session (handle session start)

Request:
```json
{
  "op": "open_session",
  "username": "miguel",
  "rhost": "192.168.1.100",
  "timestamp": 1642262445
}
```

Response:
```json
{
  "status": "success",
  "message": "Session opened for user miguel"
}
```

Error Response:
```json
{
  "status": "error",
  "error": "user explicitly denied"
}
```

#### close_session (handle session end)

Request:
```json
{
  "op": "close_session",
  "username": "miguel",
  "rhost": "192.168.1.100",
  "timestamp": 1642262545
}
```

Response:
```json
{
  "status": "success",
  "message": "Session closed for user miguel"
}
```

### User Provisioning

When `user_provisioning.retain_users` is enabled, the daemon automatically provisions users to `/etc/passwd` and `/etc/group` when sessions are opened. When `user_provisioning.reclaim_users` is enabled, users are removed when sessions close.

Configuration:
```yaml
user_provisioning:
  retain_users: true   # Add users to passwd file when session opens
  reclaim_users: false # Remove users from passwd file when session closes (testing)
```

## Logs

The daemon logs all requests and responses to stdout. You can redirect to a file:

```bash
sudo ./warp_portal_daemon > /var/log/warp_portal_daemon.log 2>&1 &
```

## Development

To extend this daemon:

1. Modify the `staticUsers` and `staticGroups` maps to add more test data
2. Add new operation handlers in the switch statement
3. Update the protocol documentation

This is a testing/development daemon. In production, you would replace the static data with actual authentication backends (LDAP, database, etc.).
