# Warp Portal PAM Module

A comprehensive PAM module (`pam_sockauth.so`) that provides both passwordless sudo authentication and SSH session lifecycle tracking by communicating with the Warp Portal daemon via Unix domain sockets.

## Overview

The Warp Portal PAM Module combines two essential authentication and monitoring functions:

1. **Authentication Management**: Passwordless sudo/su for authorized users
2. **Session Lifecycle Tracking**: SSH session open/close monitoring with remote host detection

### Key Components

- **pam_sockauth.c**: Unified PAM module handling authentication and session management
- **JSON Protocol**: Structured communication with the Warp Portal daemon
- **Comprehensive Logging**: Detailed audit trails for security and troubleshooting
- **Configuration Tools**: Automated installation and configuration management

## Architecture

### High-Level System Integration

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Sudo/Su Command │───▶│                 │───▶│                 │
│ SSH Login       │───▶│  PAM sockauth   │───▶│ Warp Portal     │
│ Session Events  │───▶│     Module      │───▶│    Daemon       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ PAM Operations  │    │ JSON Protocol   │    │ Centralized     │
│ • authenticate  │    │ • checksudo     │    │ • sudoers list  │
│ • open_session  │    │ • session ops   │    │ • session logs  │
│ • close_session │    │ • user/host     │    │ • audit trail   │
│ • acct_mgmt     │    │ • timestamps    │    │ • config mgmt   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Detailed PAM Module Flow

```
┌─────────────────┐
│  System Event   │
│ (sudo, ssh, su) │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PAM Stack     │───▶│  pam_sockauth   │───▶│ Socket Connect  │
│ /etc/pam.d/*    │    │    Module       │    │ /run/warp_*     │
└─────────────────┘    └─────────┬───────┘    └─────────┬───────┘
                                 │                      │
                                 ▼                      ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │ Function Router │    │   JSON Request  │
                    │ • authenticate  │    │ • op: checksudo │
                    │ • open_session  │    │ • op: session   │
                    │ • close_session │    │ • user, host    │
                    │ • acct_mgmt     │    │ • timestamp     │
                    └─────────┬───────┘    └─────────┬───────┘
                              │                      │
                              ▼                      ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │ Request Handler │    │  Daemon Process │
                    │ • check_sudo_*  │    │ • Parse JSON    │
                    │ • send_session_*│    │ • Check Config  │
                    │ • get_pam_env_* │    │ • sudoers list  │
                    │ • log_message   │    │ • Log event     │
                    └─────────┬───────┘    └─────────┬───────┘
                              │                      │
                              ▼                      ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │ Response Parse  │    │ JSON Response   │
                    │ • ALLOW/DENY    │    │ • status: ok    │
                    │ • success/fail  │    │ • message       │
                    │ • Fallback      │    │ • error details │
                    └─────────┬───────┘    └─────────┬───────┘
                              │                      │
                              ▼                      ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │  PAM Return     │    │  System Logs    │
                    │ • PAM_SUCCESS   │    │ • /var/log/*    │
                    │ • PAM_AUTH_ERR  │    │ • syslog        │
                    │ • PAM_*_ERR     │    │ • audit trail   │
                    └─────────────────┘    └─────────────────┘
```

### Authentication Flow Detail

```
User runs 'sudo command'
         │
         ▼
┌─────────────────┐
│ PAM auth stack  │ ← /etc/pam.d/sudo
│ calls module    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ pam_sm_auth()   │
│ • Get username  │
│ • Create JSON   │
│ • Send request  │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Daemon checks   │
│ config.yaml:    │
│   sudoers:      │ ── Check if user in list
│   - admin       │
│   - miguel      │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Response:       │
│ ALLOW → sudo    │ ── Command executes
│ DENY  → fail    │ ── Falls back to password
└─────────────────┘
```

### Session Tracking Flow Detail

```
User SSH connects
         │
         ▼
┌─────────────────┐
│ PAM session     │ ← /etc/pam.d/sshd
│ stack calls     │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ pam_sm_open()   │
│ • Get username  │
│ • Get PAM_RHOST │
│ • Get SSH_CLIENT│
│ • Extract IP    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Send session    │
│ request:        │
│ • op: session   │
│ • type: open    │
│ • user: miguel  │
│ • rhost: IP     │
│ • timestamp     │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Daemon logs     │
│ • Session start │
│ • User tracking │
│ • IP logging    │
│ • Audit trail   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ SSH session     │ ── User works normally
│ continues...    │
└─────────┬───────┘
          │ (logout)
          ▼
┌─────────────────┐
│ pam_sm_close()  │
│ • Same process  │
│ • type: close   │
│ • Session end   │
└─────────────────┘
```

## Features

### Authentication Management
- **Passwordless Sudo**: Authorized users can use sudo without password entry
- **Su Integration**: Optional su command integration
- **Fallback Safety**: Graceful fallback to standard authentication if daemon unavailable
- **JSON Communication**: Structured requests to daemon for authorization decisions

### Session Lifecycle Tracking  
- **SSH Session Monitoring**: Tracks when users establish and close SSH sessions
- **Remote Host Detection**: Captures source IP addresses for security auditing
- **Session Duration**: Timestamps for start/end times
- **Multi-Environment**: Works with local and remote sessions

### Security Features
- **Centralized Control**: All permissions managed through daemon configuration
- **Comprehensive Logging**: Detailed audit trail of all authentication and session events
- **Secure Protocols**: Unix domain socket communication with JSON validation
- **Graceful Degradation**: System remains functional if daemon is unavailable

### Monitoring and Debugging
- **Real-time Logs**: Live monitoring of authentication attempts and session events
- **Debug Mode**: Detailed protocol tracing for troubleshooting
- **Status Monitoring**: Built-in health checks and configuration validation
- **Syslog Integration**: System-wide log integration for centralized monitoring

## Installation

### 1. Install Dependencies

```bash
make install-deps
```

This installs the required PAM development libraries and json-c.

### 2. Build the Module

```bash
make all
```

### 3. Install the Module

```bash
make install
```

This installs the PAM module to the appropriate system directory (automatically detected).

## Configuration

### ⚠️ CRITICAL SECURITY WARNING ⚠️

**ALWAYS keep a root session open while configuring PAM modules. Incorrect configuration can lock you out of sudo access.**

### 1. Backup Current Configuration

```bash
make backup-pam
```

### 2. Get Configuration Instructions

```bash
make configure-pam
```

This will show you exactly what to add to your PAM configuration files and check for conflicts.

### 3. Configure Sudo Authentication (Required)

Edit `/etc/pam.d/sudo`:

```bash
sudo nano /etc/pam.d/sudo
```

**Add these lines:**

```
auth    sufficient pam_sockauth.so
session required   pam_sockauth.so
```

**Example complete configuration:**

```
auth    sufficient pam_sockauth.so
auth    required   pam_unix.so
account required   pam_unix.so
session required   pam_sockauth.so
```

### 4. Configure SSH Session Tracking (Optional)

Edit `/etc/pam.d/sshd`:

```bash
sudo nano /etc/pam.d/sshd
```

**Add session tracking:**

```
session required pam_sockauth.so
```

**Example SSH configuration:**

```
# Authentication
auth       required     pam_sepermit.so
auth       substack     password-auth

# Account management
account    required     pam_sepermit.so
account    sufficient   pam_permit.so
account    required     pam_unix.so

# Session management - ADD THIS LINE
session    required     pam_sockauth.so
session    optional     pam_systemd.so
session    substack     password-auth
```

### 5. Configure Su (Optional)

Edit `/etc/pam.d/su`:

```bash
sudo nano /etc/pam.d/su
```

**Add these lines:**

```
auth    sufficient pam_sockauth.so
session required   pam_sockauth.so
```

### Configuration Key Points

- **Use `sufficient`** for auth to allow fallback authentication
- **Use `required`** for session to ensure tracking
- **Place pam_sockauth.so appropriately** in the PAM stack
- **Test thoroughly** before closing your current session

## Protocol Details

### Authentication Requests

**Sudo Permission Check:**
```json
{
  "op": "checksudo",
  "username": "miguel"
}
```

**Response:**
```
ALLOW
```
or
```
DENY
```

### Session Management Requests

**Session Open:**
```json
{
  "op": "session",
  "pam_type": "open_session",
  "username": "miguel",
  "rhost": "192.168.1.100",
  "timestamp": 1642262445
}
```

**Session Close:**
```json
{
  "op": "session",
  "pam_type": "close_session", 
  "username": "miguel",
  "rhost": "192.168.1.100",
  "timestamp": 1642262545
}
```

**Session Response:**
```json
{
  "status": "success",
  "message": "Session logged"
}
```

## Testing

### 1. Check Installation Status

```bash
make status
```

### 2. Test the Module

```bash
make test
```

### 3. Manual Testing

**Test sudo authentication:**

```bash
sudo -l
sudo whoami
```

**Test session tracking (SSH from another machine):**

```bash
ssh user@this-server
# Check logs immediately
tail -f /var/log/pam_sockauth.log
```

### 4. Monitor Logs

```bash
make logs
```

This shows real-time authentication attempts, session events, and results.

## Configuration Management

### Adding Users to Sudoers

Users must be in the sudoers list in your daemon configuration to gain passwordless sudo access.

Edit `/etc/warp_portal/config.yaml`:

```yaml
# Users allowed to use sudo (passwordless sudo access)
sudoers:
  - admin
  - miguel
  - alice # Add new users here
```

**Note:** Only users explicitly listed in the `sudoers` section will be granted passwordless sudo access.

Restart the daemon to reload configuration:

```bash
sudo systemctl restart warp_portal_daemon
```

## Logging and Monitoring

### Log Files
- **Module logs**: `/var/log/pam_sockauth.log`
- **Syslog**: Messages also sent to system syslog  
- **SSH logs**: Standard SSH logs in `/var/log/auth.log`

### Log Levels
- **INFO**: Normal authentication and session events
- **DEBUG**: Protocol details and request/response traces
- **WARN**: Non-fatal errors (daemon unavailable, denied access)
- **ERROR**: Critical failures and system errors

### Example Log Output

```
[2024-01-15 10:30:45] INFO: PAM authentication attempt for user: miguel
[2024-01-15 10:30:45] DEBUG: Sending JSON request: {"op":"checksudo","username":"miguel"}
[2024-01-15 10:30:45] DEBUG: Received response: ALLOW
[2024-01-15 10:30:45] INFO: JSON response: Authentication successful for user: miguel
[2024-01-15 10:30:45] INFO: Opening session for user: miguel from 192.168.1.100
[2024-01-15 10:30:45] DEBUG: Sending session request: {"op":"session","pam_type":"open_session"...}
[2024-01-15 10:30:45] INFO: Session open request completed successfully
[2024-01-15 10:35:12] INFO: Closing session for user: miguel from 192.168.1.100
```

## Security Features

### 1. Secure Authentication
- No password required for authorized users
- Falls back to standard authentication if daemon unavailable
- Denies access by default on any error
- Real-time authorization checks

### 2. Session Security
- Complete session lifecycle tracking
- Remote host identification for audit trails
- Timestamp precision for session duration analysis
- Non-blocking operation to maintain system performance

### 3. Comprehensive Logging
- All authentication attempts logged with context
- Session events with user and remote host details
- Protocol-level debugging for security analysis
- Integration with system syslog for centralized monitoring

### 4. Safe Fallback
- Uses `sufficient` PAM control to allow fallback authentication
- Sessions proceed even if daemon unavailable (with logging)
- Graceful error handling prevents system lockout
- Maintains system security if module fails

### 5. File Permissions
- PAM module installed with root ownership (root:root)
- Restrictive permissions (644) prevent unauthorized modification
- Log files properly secured with appropriate access controls

## Troubleshooting

### 1. Module Not Working

Check installation status:
```bash
make status
```

Verify PAM module exists:
```bash
ls -la /lib/security/pam_sockauth.so
# or  
ls -la /lib/x86_64-linux-gnu/security/pam_sockauth.so
```

### 2. Authentication Failing

1. **Check daemon status:**
   ```bash
   sudo systemctl status warp_portal_daemon
   ```

2. **Check socket exists:**
   ```bash
   ls -la /run/warp_portal.sock
   ```

3. **Test socket connectivity:**
   ```bash
   echo '{"op":"checksudo","username":"testuser"}' | socat - UNIX-CONNECT:/run/warp_portal.sock
   ```

4. **Monitor authentication logs:**
   ```bash
   tail -f /var/log/pam_sockauth.log
   ```

5. **Check user is in sudoers list:**
   ```bash
   sudo cat /etc/warp_portal/config.yaml | grep -A 10 "sudoers:"
   ```

### 3. Session Tracking Not Working

1. **Check PAM configuration includes session management:**
   ```bash
   grep pam_sockauth.so /etc/pam.d/sshd
   ```

2. **Monitor session logs during SSH connection:**
   ```bash
   tail -f /var/log/pam_sockauth.log | grep -E "(Opening|Closing) session"
   ```

3. **Test PAM environment variables:**
   ```bash
   # SSH with verbose logging
   ssh -v user@server
   ```

### 4. Locked Out of Sudo

If you get locked out:

1. **Use existing root session** (this is why you kept one open)
2. **Boot into single-user mode** if necessary  
3. **Restore PAM configuration from backup:**
   ```bash
   sudo cp /etc/pam.d/sudo.bak.YYYYMMDD_HHMMSS /etc/pam.d/sudo
   ```

### 5. Debug Mode

Build with debug symbols:
```bash
make debug
sudo make install
```

Check detailed logs:
```bash
sudo journalctl -f | grep pam_sockauth
```

## Advanced Configuration

### Environment Variable Capture

The module automatically captures these PAM environment variables:
- `PAM_USER`: Username for session/authentication
- `PAM_RHOST`: Remote host IP address
- `SSH_CLIENT`: Alternative remote client information
- `PAM_TYPE`: Dynamically determined (open_session/close_session)

### Multiple PAM Integration

The module can be configured for different use cases:

**Sudo Only:**
```
# /etc/pam.d/sudo
auth sufficient pam_sockauth.so
```

**Session Tracking Only:**  
```
# /etc/pam.d/sshd
session required pam_sockauth.so
```

**Complete Integration:**
```
# Multiple PAM files
auth    sufficient pam_sockauth.so
session required   pam_sockauth.so
```

## File Locations

- **PAM Module**: `/lib/security/pam_sockauth.so` (or `/lib64/security/`)
- **Log File**: `/var/log/pam_sockauth.log`
- **Socket**: `/run/warp_portal.sock`
- **Configuration**: `/etc/warp_portal/config.yaml`
- **PAM Configs**: `/etc/pam.d/sudo`, `/etc/pam.d/su`, `/etc/pam.d/sshd`

## Makefile Targets

- `make all` - Build the PAM module
- `make install` - Install to system PAM directory  
- `make uninstall` - Remove from system
- `make configure-pam` - Show configuration instructions and check for conflicts
- `make backup-pam` - Backup current PAM configuration
- `make test` - Test module installation and connectivity
- `make status` - Show installation and configuration status  
- `make logs` - Show real-time authentication and session logs
- `make install-deps` - Install PAM development dependencies
- `make clean` - Remove build files
- `make help` - Show all available targets

## Integration with Warp Portal Components

This PAM module works alongside:

- **NSS Module**: Provides user/group information via same socket
- **SSH Module**: Handles SSH key authentication 
- **Sudo Plugin**: Custom sudo policy enforcement
- **Warp Portal Daemon**: Central authentication and session management service

All modules use the same socket and configuration for consistent authentication across the system.

## Best Practices

### Development and Testing
1. **Always test in a safe environment first**
2. **Keep backup sessions open during configuration**
3. **Use staging environment that mirrors production**
4. **Test all PAM functions (auth, session, account)**

### Production Deployment  
1. **Monitor logs during initial deployment**
2. **Use `sufficient` not `required` for auth PAM control**
3. **Regularly backup PAM configurations**
4. **Ensure daemon is properly monitored and has high availability**
5. **Document rollback procedures**

### Security Considerations
1. **Limit sudoers list to essential users only**
2. **Monitor session logs for unusual patterns**  
3. **Regular security audits of authentication logs**
4. **Keep daemon configuration secure and backed up**

## Production Deployment

For production environments:

### Pre-Deployment
1. **Test thoroughly** in staging environment identical to production
2. **Have rollback plan** ready with tested procedures
3. **Prepare monitoring** for authentication and session events
4. **Document emergency procedures** for authentication failures

### During Deployment
1. **Deploy during maintenance window**  
2. **Monitor logs** in real-time during deployment
3. **Test immediately** after configuration changes
4. **Keep emergency access** available throughout process

### Post-Deployment  
1. **Monitor authentication patterns** for first 24-48 hours
2. **Verify session tracking** is working correctly
3. **Check log rotation** and storage capacity
4. **Document operational procedures** for ongoing maintenance

## Monitoring and Maintenance

### Log Rotation
Configure log rotation for PAM logs:

```bash
# Create /etc/logrotate.d/pam-sockauth
cat > /etc/logrotate.d/pam-sockauth << 'EOF'
/var/log/pam_sockauth.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
```

### Health Monitoring
- Monitor daemon socket availability
- Check authentication success/failure rates
- Track session patterns for anomaly detection
- Verify log file growth and rotation

### Updates and Maintenance
```bash
# Update the module
cd /path/to/warp-portal/pam
git pull
make clean && make all  
sudo make install

# Restart services if needed
sudo systemctl restart sshd  # Only if SSH config changed
```

## Support and Troubleshooting

### Getting Help
- Check logs first: `make logs`
- Verify daemon status: `sudo systemctl status warp-portal-daemon`
- Test connectivity: `make test`
- Review configuration: `make configure-pam`

### Reporting Issues
When reporting issues, include:
- Operating system and version
- PAM configuration files (`/etc/pam.d/sudo`, `/etc/pam.d/sshd`)
- Module logs (sanitized to remove sensitive information)
- Daemon logs and status
- Steps to reproduce the issue

## License

This module is part of the Warp Portal project. See project documentation for licensing details.