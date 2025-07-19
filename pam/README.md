# PAM Socket Authentication Module

This PAM module (`pam_sockauth.so`) provides passwordless sudo and su authentication by communicating with the Warp Portal daemon via Unix domain sockets. Users configured in the sudoers list can gain elevated privileges without entering a password.

## Overview

The PAM Socket Authentication Module consists of:

- **pam_sockauth.c**: A PAM module that communicates with the Warp Portal daemon
- **Enhanced daemon**: Handles `checksudo` requests and returns ALLOW/DENY based on sudoers list membership
- **Configuration tools**: Makefile targets to install, configure, and manage the PAM module

## How It Works

1. **Sudo/Su Attempt**: When a user runs `sudo` or `su`, PAM calls the sockauth module
2. **Socket Request**: The module sends a JSON request to the Warp Portal daemon via Unix socket
3. **Sudoers Check**: The daemon checks if the user is in the sudoers list in the configuration file
4. **Response**: The daemon responds with "ALLOW" or "DENY"
5. **Authentication**: PAM grants or denies access based on the response

## Installation

### 1. Install Dependencies

```bash
make install-deps
```

This installs the required PAM development libraries.

### 2. Build the Module

```bash
make all
```

### 3. Install the Module

```bash
make install
```

This installs the PAM module to the appropriate system directory (automatically detected).

## PAM Configuration

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

### 3. Configure sudo (Required)

Edit `/etc/pam.d/sudo`:

```bash
sudo nano /etc/pam.d/sudo
```

**Add this line at the TOP of the file:**

```
auth    sufficient pam_sockauth.so
```

**Example complete configuration:**

```
auth    sufficient pam_sockauth.so
auth    required   pam_unix.so
account required   pam_unix.so
```

### 4. Configure su (Optional)

Edit `/etc/pam.d/su`:

```bash
sudo nano /etc/pam.d/su
```

**Add this line at the TOP of the file:**

```
auth    sufficient pam_sockauth.so
```

### 5. Key Configuration Points

- **Use `sufficient`** not `required` to allow fallback authentication
- **Place pam_sockauth.so FIRST** before other auth modules
- **Test thoroughly** before closing your current session

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

Test sudo access:

```bash
sudo -l
```

Test su access:

```bash
su - root
```

### 4. Monitor Logs

```bash
make logs
```

This shows real-time authentication attempts and results.

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

## Request/Response Format

### Request to Daemon

```json
{
  "op": "checksudo",
  "username": "miguel"
}
```

### Response from Daemon

```
ALLOW
```

or

```
DENY
```

## Security Features

### 1. Secure Authentication

- No password required for authorized users
- Falls back to standard authentication if daemon unavailable
- Denies access by default on any error

### 2. Comprehensive Logging

- All authentication attempts logged to `/var/log/pam_sockauth.log`
- Includes username, timestamp, and result
- Integrates with system syslog

### 3. Safe Fallback

- Uses `sufficient` PAM control to allow fallback authentication
- Gracefully handles daemon unavailability
- Maintains system security if module fails

### 4. File Permissions

- PAM module installed with root ownership (root:root)
- Restrictive permissions (644) prevent unauthorized modification
- Log files properly secured

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

3. **Monitor authentication logs:**

   ```bash
   tail -f /var/log/pam_sockauth.log
   ```

4. **Check user is in sudoers list:**
   ```bash
   # In daemon config
   sudo cat /etc/warp_portal/config.yaml | grep -A 5 "sudoers:"
   ```

### 3. Locked Out of Sudo

If you get locked out:

1. **Use existing root session** (this is why you kept one open)
2. **Boot into single-user mode** if necessary
3. **Restore PAM configuration from backup:**
   ```bash
   sudo cp /etc/pam.d/sudo.bak.YYYYMMDD_HHMMSS /etc/pam.d/sudo
   ```

### 4. Debug Mode

Build with debug symbols:

```bash
make debug
```

Check detailed logs:

```bash
sudo journalctl -f | grep pam_sockauth
```

## File Locations

- **PAM Module**: `/lib/security/pam_sockauth.so` (or `/lib64/security/`)
- **Log File**: `/var/log/pam_sockauth.log`
- **Socket**: `/run/warp_portal.sock`
- **Configuration**: `/etc/warp_portal/config.yaml`
- **PAM Config**: `/etc/pam.d/sudo`, `/etc/pam.d/su`

## Makefile Targets

- `make all` - Build the PAM module
- `make install` - Install to system PAM directory
- `make uninstall` - Remove from system
- `make configure-pam` - Show configuration instructions and check for conflicts
- `make backup-pam` - Backup current PAM configuration
- `make test` - Test module installation and connectivity
- `make status` - Show installation and configuration status
- `make logs` - Show real-time authentication logs
- `make install-deps` - Install PAM development dependencies
- `make clean` - Remove build files
- `make help` - Show all available targets

## Integration with Other Modules

This PAM module works alongside:

- **NSS Module**: Provides user/group information
- **SSH Module**: Handles SSH key authentication
- **Warp Portal Daemon**: Central authentication service

All modules use the same socket and configuration for consistent authentication across the system.

## Best Practices

1. **Always test in a safe environment first**
2. **Keep backup sessions open during configuration**
3. **Monitor logs during initial deployment**
4. **Use `sufficient` not `required` for PAM control**
5. **Regularly backup PAM configurations**
6. **Ensure daemon is properly monitored and has high availability**

## Production Deployment

For production environments:

1. **Test thoroughly** in staging environment
2. **Have rollback plan** ready
3. **Monitor authentication logs** closely
4. **Ensure daemon high availability**
5. **Regular backup** of PAM configurations
6. **Document emergency procedures** for authentication failures
