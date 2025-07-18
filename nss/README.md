# NSS Socket Plugin

## Overview

This NSS plugin forwards user and group lookup requests to a Go daemon via Unix domain socket. The plugin implements the NSS interface to resolve user accounts and groups by communicating with a separate Go process that handles the actual authentication logic.

## Features

- Thread-safe implementation using pthread mutexes
- Comprehensive logging to `/var/log/nss_socket.log`
- JSON-based communication protocol with Go daemon
- Error handling for daemon unavailability
- Support for both user (passwd) and group lookups

## Architecture

The plugin implements the following NSS functions:

### Passwd Functions
- `_nss_socket_getpwnam_r` - Lookup user by name
- `_nss_socket_getpwuid_r` - Lookup user by UID
- `_nss_socket_setpwent` - Initialize passwd enumeration (no-op)
- `_nss_socket_endpwent` - Finalize passwd enumeration (no-op)
- `_nss_socket_getpwent_r` - Enumerate passwd entries (not supported)

### Group Functions
- `_nss_socket_getgrnam_r` - Lookup group by name
- `_nss_socket_getgrgid_r` - Lookup group by GID
- `_nss_socket_setgrent` - Initialize group enumeration (no-op)
- `_nss_socket_endgrent` - Finalize group enumeration (no-op)
- `_nss_socket_getgrent_r` - Enumerate group entries (not supported)

## Communication Protocol

The plugin communicates with the Go daemon via Unix domain socket at `/run/nss-forward.sock` using JSON messages:

### User Lookup by Name
```json
{"op": "getpwnam", "username": "miguel"}
```

### User Lookup by UID
```json
{"op": "getpwuid", "uid": 1000}
```

### Group Lookup by Name
```json
{"op": "getgrnam", "groupname": "users"}
```

### Group Lookup by GID
```json
{"op": "getgrgid", "gid": 100}
```

### Response Format

#### Successful User Response
```json
{
  "status": "success",
  "user": {
    "name": "miguel",
    "uid": 1000,
    "gid": 100,
    "gecos": "Miguel Campos",
    "dir": "/home/miguel",
    "shell": "/bin/bash"
  }
}
```

#### Successful Group Response
```json
{
  "status": "success",
  "group": {
    "name": "users",
    "gid": 100,
    "members": ["miguel", "john"]
  }
}
```

#### Error Response
```json
{
  "status": "error",
  "message": "User not found"
}
```

## Installation

### Prerequisites

Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install build-essential libjson-c-dev
```

### Build and Install

1. Clone or download the source code
2. Build the plugin:
```bash
make
```

3. Install the plugin:
```bash
sudo make install
```

This will:
- Copy `libnss_socket.so.2` to `/lib/x86_64-linux-gnu/`
- Update the linker cache with `ldconfig`

### Configuration

Edit `/etc/nsswitch.conf` to include the socket plugin:

```
passwd: files socket
group: files socket
```

The order matters - `files` will be checked first, then `socket`.

### Go Daemon Setup

You need to implement a Go daemon that:
1. Listens on Unix domain socket `/run/nss-forward.sock`
2. Handles JSON requests as described in the protocol section
3. Returns appropriate JSON responses

Example Go daemon structure:
```go
func main() {
    ln, err := net.Listen("unix", "/run/nss-forward.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()
    
    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }
        go handleConnection(conn)
    }
}
```

## Logging

The plugin logs to `/var/log/nss_socket.log`. Make sure the log file is writable:

```bash
sudo touch /var/log/nss_socket.log
sudo chmod 666 /var/log/nss_socket.log
```

Log entries include:
- Connection attempts to the Go daemon
- Successful and failed lookups
- JSON parsing errors
- Socket communication errors

## Testing

Test the plugin with standard tools:

```bash
# Test user lookup
getent passwd miguel

# Test group lookup  
getent group users

# Test with id command
id miguel
```

## Troubleshooting

### Plugin Not Loading
- Check that `libnss_socket.so.2` exists in `/lib/x86_64-linux-gnu/`
- Verify `/etc/nsswitch.conf` configuration
- Run `ldconfig` to update linker cache

### Go Daemon Not Responding
- Check that the Go daemon is running
- Verify socket permissions at `/run/nss-forward.sock`
- Check logs at `/var/log/nss_socket.log`

### Permission Issues
- Ensure log file is writable: `sudo chmod 666 /var/log/nss_socket.log`
- Check socket permissions and ownership

## Uninstallation

Remove the plugin:
```bash
sudo make uninstall
```

Remove the `socket` entry from `/etc/nsswitch.conf`.

## Security Considerations

- The Unix domain socket should have appropriate permissions
- The Go daemon should validate all input
- Consider rate limiting and DOS protection in the Go daemon
- Log files may contain sensitive information - set appropriate permissions

## Thread Safety

The plugin is thread-safe:
- Uses pthread mutexes for log file access
- No global state modification
- Local variables used for temporary data storage
- JSON parsing is done per-request with local objects