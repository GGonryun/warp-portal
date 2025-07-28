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
- **sudo**: Check if user has sudo privileges (also supports legacy "checksudo")

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

## Cache Configuration

The daemon now uses an NSS cache module instead of direct /etc/passwd provisioning for better performance and reliability:

```yaml
# Cache settings for NSS cache module (replaces user_provisioning)
cache:
  enabled: true # Enable cache population (default: true)
  refresh_interval: 24 # Hours between full cache refresh (default: 24)
  cache_directory: "/tmp/warp_portal" # Cache directory path (default: /tmp/warp_portal)
  on_demand_update: true # Update cache when users accessed via socket (default: true)
```

**Benefits of NSS Cache Module:**
- No more `/etc/passwd` modification failures
- Better performance through local file caching
- Automatic refresh on configurable intervals
- On-demand population when users are accessed
- Reduced load on HTTP providers

## Cache Implementation Tradeoffs

The Warp Portal system offers two NSS modules with different performance and consistency characteristics:

### NSS Socket Module vs NSS Cache Module

**NSS Socket Module (`nss_socket`):**
- ✅ **Always Fresh Data**: Every lookup queries the daemon directly, ensuring up-to-the-second accuracy
- ✅ **Real-time Updates**: Permission changes are immediately reflected in all lookups
- ✅ **No Stale Data**: Users removed from the system cannot authenticate until cache refresh
- ❌ **Higher Latency**: Each lookup requires socket communication and potentially HTTP API calls
- ❌ **Network Dependency**: SSH logins fail if daemon is unreachable or HTTP provider is down
- ❌ **Increased Load**: Every `getent passwd` or SSH login hits the backend provider

**NSS Cache Module (`nss_cache`):**
- ✅ **High Performance**: Lookups hit local files, typically 10-100x faster than socket calls
- ✅ **Offline Resilience**: SSH logins work even if daemon or HTTP provider is unavailable
- ✅ **Reduced Backend Load**: Most lookups served from cache, reducing HTTP API pressure
- ✅ **System Stability**: Less likely to cause authentication timeouts during network issues
- ❌ **Potential Staleness**: Data may be up to `refresh_interval` hours old
- ❌ **Permission Lag**: Removed users might briefly remain accessible until cache updates
- ❌ **Disk Space**: Requires cache files and directory (typically <1MB)

### Deployment Strategies

**High-Security Environments (Real-time Updates Critical):**
```
# /etc/nsswitch.conf - Prioritize accuracy over performance
passwd: files nss_socket
group:  files nss_socket
```
- Use when immediate permission revocation is critical
- Accept higher latency for guaranteed fresh data
- Ensure robust network connectivity to HTTP providers

**High-Performance Environments (Speed Critical):**
```
# /etc/nsswitch.conf - Prioritize performance over staleness
passwd: files nss_cache
group:  files nss_cache
```
- Use for high-frequency SSH connections or user lookups
- Accept potential staleness for significant performance gains
- Set shorter `refresh_interval` (1-6 hours) for faster updates

**Hybrid Approach (Balanced):**
```
# /etc/nsswitch.conf - Best of both worlds
passwd: files nss_cache nss_socket
group:  files nss_cache nss_socket
```
- Cache serves most lookups (fast)
- Socket provides fallback for cache misses (accurate)
- Ideal for most production environments

### Cache Staleness Management

The cache refresh mechanism minimizes staleness impact:

**Automatic Background Refresh:**
- Full cache refresh every `refresh_interval` hours (default: 24h for file, 6h for HTTP)
- Atomic file replacement prevents partial/corrupted reads
- Continues using old cache if refresh fails (resilience)

**On-Demand Population:**
- New users added to cache immediately when accessed via daemon socket
- `open_session` events trigger cache population for active users
- Reduces staleness window for actively used accounts

**Staleness Examples:**
```bash
# Scenario: User removed from HTTP API at 9:00 AM, cache refreshes at 6:00 PM

# 9:00 AM - 6:00 PM: User still appears in cache
getent passwd removed_user  # ✓ Returns user (stale data)
ssh removed_user@server     # ✓ Might succeed if using nss_cache only

# 6:00 PM onwards: User removed from cache
getent passwd removed_user  # ✗ User not found
ssh removed_user@server     # ✗ Authentication fails
```

### Configuration Recommendations

**For File Providers:**
```yaml
cache:
  enabled: true
  refresh_interval: 24  # Daily refresh sufficient for local files
  on_demand_update: true
```

**For HTTP Providers:**
```yaml
cache:
  enabled: true
  refresh_interval: 6   # More frequent refresh for remote data
  on_demand_update: true
```

**High-Security Environments:**
```yaml
cache:
  enabled: true
  refresh_interval: 1   # Hourly refresh for faster updates
  on_demand_update: true
```

### When to Disable Caching

Consider disabling the cache module (`cache.enabled: false`) when:
- **Immediate Consistency Required**: Zero tolerance for stale data
- **Low Lookup Frequency**: Performance gains don't justify complexity
- **Unreliable Storage**: Cache directory on unreliable filesystem
- **Debugging**: Troubleshooting authentication issues

**Disable Cache Configuration:**
```yaml
cache:
  enabled: false  # Forces all lookups through nss_socket
```

In practice, most deployments benefit from enabling the cache with appropriate refresh intervals, as the performance and resilience gains typically outweigh the brief staleness window. The hybrid NSS configuration (`nss_cache nss_socket`) provides an excellent balance for production systems.

## HTTP Provider Configuration

For production deployments, the daemon can fetch user/group data from HTTP APIs instead of local files:

```yaml
provider:
  type: http
  config:
    url: "https://api.p0.app/portal"
    timeout: 10 # HTTP request timeout in seconds (default: 10)
    cache_ttl: 60 # Provider-level cache timeout in seconds (default: 300)

# Logging verbosity: error, warn, info, debug, trace (default: info)
log_level: info

# Cache settings (CRITICAL for HTTP provider performance)
cache:
  enabled: true # Enable cache population (default: true)
  refresh_interval: 6 # Hours between full cache refresh (more frequent for HTTP)
  cache_directory: "/tmp/warp_portal" # Cache directory path
  on_demand_update: true # Update cache when users accessed via socket

# Users allowed to use sudo (managed via HTTP API responses)
sudoers:
  - admin
  - miguel

# System users/groups to automatically deny (performance optimization)
deny_users:
  - mail
  - daemon
  - bin
  - sys
  - nobody
  # ... (full list in config.http.yaml)

deny_groups:
  - mail
  - daemon
  - bin
  - sys
  - nogroup
  # ... (full list in config.http.yaml)
```

### HTTP API Endpoints

The HTTP provider expects the following REST API endpoints:

| Method | Endpoint | Description | Request Body |
|--------|----------|-------------|--------------|
| POST | `/user` | Get user by username or UID | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "username": "alice"}` OR `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "uid": "1000"}` |
| POST | `/group` | Get group by name or GID | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "groupname": "developers"}` OR `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "gid": "1000"}` |
| POST | `/keys` | Get SSH keys for user | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "username": "alice"}` |
| POST | `/users` | List all users | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890}` |
| POST | `/groups` | List all groups | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890}` |
| POST | `/sudo` | Check sudo privileges | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "username": "alice"}` |
| POST | `/initgroups` | Get user's groups | `{"fingerprint": "SHA256:...", "public_key": "ssh-ed25519 ...", "timestamp": 1234567890, "username": "alice"}` |

### Sample HTTP Responses

**User Response (`/user`):**
```json
{
  "name": "alice",
  "uid": 2001,
  "gid": 2001,
  "gecos": "Alice Smith",
  "dir": "/home/alice",
  "shell": "/bin/bash"
}
```

**Group Response (`/group`):**
```json
{
  "name": "developers",
  "gid": 3000,
  "members": ["alice", "bob", "miguel"]
}
```

**SSH Keys Response (`/keys`):**
```json
[
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMz9K1qL3x4vWfZ8w... alice@desktop",
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx1Qr7vKuIl8X2wXIv... alice@mobile"
]
```

**Sudo Check Response (`/sudo`):**
```json
{
  "allowed": true
}
```

**User Groups Response (`/initgroups`):**
```json
[1000, 1001, 3000, 4500, 64201]
```

### Machine Authentication

All HTTP requests include machine authentication via SSH host key:

- **`fingerprint`**: SHA256 hash of the machine's SSH host key (e.g., `"SHA256:abc123def456..."`)
- **`public_key`**: Full SSH public key of the machine (e.g., `"ssh-ed25519 AAAAC3NzaC..."`)
- **`timestamp`**: Unix timestamp when the request was made

This allows the HTTP API to identify and authorize specific machines.

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

#### sudo (check sudo privileges)

Request:
```json
{
  "op": "sudo",
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
