# NSS Go Daemon

This is a placeholder Go daemon that provides static user and group data for testing the NSS socket plugin.

## Features

- Unix domain socket server on `/run/nss-forward.sock`
- JSON request/response protocol
- Static test data for users and groups
- Graceful shutdown handling
- Comprehensive logging

## Static Test Data

### Users

- `miguel` (UID: 1000, GID: 1000) - Miguel Campos
- `testuser` (UID: 1001, GID: 1001) - Test User
- `admin` (UID: 1002, GID: 1002) - Administrator

### Groups

- `miguel` (GID: 1000) - members: [miguel]
- `testuser` (GID: 1001) - members: [testuser]
- `admin` (GID: 1002) - members: [admin]
- `users` (GID: 100) - members: [miguel, testuser]
- `sudo` (GID: 27) - members: [miguel, admin]

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

## Protocol

The daemon handles the following operations:

### getpwnam (lookup user by name)

Request:

```json
{ "op": "getpwnam", "username": "miguel" }
```

Response:

```json
{
  "status": "success",
  "user": {
    "name": "miguel",
    "uid": 1000,
    "gid": 1000,
    "gecos": "Miguel Campos",
    "dir": "/home/miguel",
    "shell": "/bin/bash"
  }
}
```

### getpwuid (lookup user by UID)

Request:

```json
{ "op": "getpwuid", "uid": 1000 }
```

### getgrnam (lookup group by name)

Request:

```json
{ "op": "getgrnam", "groupname": "users" }
```

Response:

```json
{
  "status": "success",
  "group": {
    "name": "users",
    "gid": 100,
    "members": ["miguel", "testuser"]
  }
}
```

### getgrgid (lookup group by GID)

Request:

```json
{ "op": "getgrgid", "gid": 100 }
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
