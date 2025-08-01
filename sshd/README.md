# SSH Authorized Keys Socket Module

This module provides dynamic SSH public key authentication by communicating with the P0 Agent daemon via Unix domain sockets. It replaces static authorized_keys files with dynamic key retrieval from an external service.

## Overview

The SSH Authorized Keys Socket Module consists of:
- **authorized_keys_socket.c**: A C program that communicates with the P0 Agent daemon to retrieve SSH public keys
- **Enhanced daemon**: The Go daemon handles `getkeys` requests and returns public keys for users
- **Configuration tools**: Makefile targets to install, configure, and manage the module

## Installation

### 1. Install Dependencies

```bash
make install-deps
```

This installs the required `json-c` development library.

### 2. Build the Module

```bash
make all
```

### 3. Install the Module

```bash
make install
```

This installs the `authorized_keys_socket` binary to `/usr/local/bin/`.

## SSH Server Configuration

### 1. Backup Current Configuration

```bash
make backup-config
```

### 2. Configure SSH Daemon

```bash
make configure-ssh
```

This command will:
- Show you the required configuration lines
- Check for conflicting configurations in `/etc/ssh/sshd_config`
- Create a backup of your current SSH configuration

### 3. Manual Configuration

Add these lines to `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
AuthenticationMethods publickey
ChallengeResponseAuthentication no
AuthorizedKeysCommand /usr/local/bin/authorized_keys_socket %t %k %u
AuthorizedKeysCommandUser root
```

**Important**: Comment out or change any conflicting settings like:
- `PasswordAuthentication yes` → `PasswordAuthentication no`
- `ChallengeResponseAuthentication yes` → `ChallengeResponseAuthentication no`
- Remove or comment existing `AuthorizedKeysCommand` directives

### 4. Restart SSH Service

```bash
make restart-ssh
```

## Testing the Module

### 1. Check Installation Status

```bash
make status
```

### 2. Test Key Retrieval

```bash
make test
```

### 3. Manual Testing

Test the module directly:

```bash
/usr/local/bin/authorized_keys_socket "ssh-rsa" "dummy_fingerprint" "miguel"
```

This should return the SSH public keys for user "miguel" if configured in the daemon.

### 4. SSH Connection Test

Try connecting via SSH:

```bash
ssh miguel@localhost
```

Monitor the daemon logs to see key retrieval requests:

```bash
tail -f /var/log/p0_agent_daemon.log
```

## How It Works

1. **SSH Connection Attempt**: When a user tries to connect via SSH, the SSH daemon calls `AuthorizedKeysCommand`
2. **Key Request**: The `authorized_keys_socket` program receives the user, key type, and fingerprint from SSH
3. **Daemon Communication**: The program sends a JSON request to the P0 Agent daemon via Unix socket (`/run/p0_agent.sock`)
4. **Key Retrieval**: The daemon looks up the user's public keys and returns them in JSON format
5. **SSH Authentication**: The returned keys are used by SSH daemon for public key authentication

## Request/Response Format

### Request to Daemon
```json
{
  "op": "getkeys",
  "username": "miguel",
  "key_type": "ssh-rsa",
  "key_fingerprint": "SHA256:..."
}
```

### Response from Daemon
```json
{
  "status": "success",
  "keys": [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... miguel@example.com",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... miguel@laptop"
  ]
}
```

## Configuration Management

### Add New Users and Keys

Edit the daemon's `staticKeys` map in `/path/to/daemon/main.go`:

```go
var staticKeys = map[string][]string{
    "miguel": {
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... miguel@example.com",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... miguel@laptop",
    },
    "newuser": {
        "ssh-rsa AAAAB3NzaC1yc2EAAAA... newuser@workstation",
    },
}
```

Then restart the daemon.

## Troubleshooting

### 1. Module Not Working

Check installation status:
```bash
make status
```

Verify the binary exists and has correct permissions:
```bash
ls -la /usr/local/bin/authorized_keys_socket
```

### 2. SSH Authentication Fails

1. Check SSH daemon configuration:
   ```bash
   sudo sshd -t
   ```

2. Monitor daemon logs:
   ```bash
   tail -f /var/log/p0_agent_daemon.log
   ```

3. Test module manually:
   ```bash
   /usr/local/bin/authorized_keys_socket "ssh-rsa" "test" "miguel"
   ```

4. Check SSH daemon logs:
   ```bash
   sudo tail -f /var/log/auth.log  # or /var/log/secure
   ```

### 3. Permission Issues

Ensure the AuthorizedKeysCommand runs as root:
```
AuthorizedKeysCommandUser root
```

The module needs to access the Unix socket at `/run/p0_agent.sock`.

### 4. Daemon Not Responding

1. Check if daemon is running:
   ```bash
   ps aux | grep p0_agent_daemon
   ```

2. Check socket exists:
   ```bash
   ls -la /run/p0_agent.sock
   ```

3. Restart the daemon if needed

## Security Considerations

- The module runs with root privileges as required by SSH's AuthorizedKeysCommand
- Communication with the daemon is via local Unix domain socket (secure)
- Only users configured in the daemon can authenticate
- Public key authentication only (passwords disabled)

## Makefile Targets

- `make all` - Build the module
- `make install` - Install to system
- `make uninstall` - Remove from system
- `make configure-ssh` - Show SSH configuration instructions
- `make restart-ssh` - Restart SSH service
- `make backup-config` - Backup SSH configuration
- `make test` - Test the module
- `make status` - Show installation status
- `make install-deps` - Install dependencies
- `make clean` - Remove build files
- `make help` - Show all available targets