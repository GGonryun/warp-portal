# Sample Cache Files

This directory contains sample cache files that demonstrate the format expected by the NSS cache module.

## Files

### `passwd.cache`
Sample user entries in standard passwd format:
- Shows various user types (admin, regular users, service accounts)
- Demonstrates different shells and home directories
- Compatible with standard passwd file format

### `group.cache`
Sample group entries in standard group format:
- Shows primary user groups
- Demonstrates shared groups with multiple members
- Includes Warp Portal reserved groups (GIDs 64200-64201)
- Shows system group examples

## Testing the NSS Cache Module

### 1. Copy Sample Files to Cache Directory

```bash
# Create cache directory
sudo mkdir -p /var/cache/warp_portal

# Copy sample files
sudo cp samples/passwd.cache /var/cache/warp_portal/
sudo cp samples/group.cache /var/cache/warp_portal/

# Set proper permissions
sudo chmod 644 /var/cache/warp_portal/*.cache
```

### 2. Install NSS Cache Module

```bash
# Build and install the module
make
sudo make install
```

### 3. Configure NSS

Add `nss_cache` to `/etc/nsswitch.conf`:

```
passwd: files nss_cache
group:  files nss_cache
```

### 4. Test Lookups

```bash
# Test user lookups
getent passwd miguel
getent passwd alice
getent passwd admin

# Test group lookups
getent group developers
getent group warp-portal-admin
getent group admins

# Test by ID
getent passwd 2000
getent group 4000

# Test enumeration
getent passwd
getent group
```

### 5. Expected Output Examples

**User lookup (`getent passwd miguel`):**
```
miguel:x:2000:2000:Miguel Campos:/home/miguel:/bin/bash
```

**Group lookup (`getent group developers`):**
```
developers:x:4000:miguel,alice,bob
```

**Group by GID (`getent group 64200`):**
```
warp-portal-admin:x:64200:admin,miguel
```

## Cache File Format

### passwd.cache Format
```
username:x:uid:gid:gecos:homedir:shell
```

- **username**: Login name
- **x**: Password placeholder (always 'x')
- **uid**: Numeric user ID
- **gid**: Primary group ID
- **gecos**: Full name/description
- **homedir**: Home directory path
- **shell**: Login shell

### group.cache Format
```
groupname:x:gid:member1,member2,member3
```

- **groupname**: Group name
- **x**: Password placeholder (always 'x')
- **gid**: Numeric group ID
- **members**: Comma-separated list of usernames (can be empty)

## Notes

- The cache files are automatically managed by the Warp Portal daemon
- These sample files are for testing the NSS module independently
- In production, cache files are populated from the configured provider (file/HTTP)
- The daemon handles atomic updates with temporary files for consistency