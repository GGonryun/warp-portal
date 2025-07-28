# NSS Cache Module

This NSS module provides cached user and group lookups from Warp Portal cache files, reducing load on HTTP providers and improving performance.

## Features

- **File-based caching**: Reads from `/var/cache/warp_portal/passwd.cache` and `/var/cache/warp_portal/group.cache`
- **Standard passwd/group format**: Compatible with existing NSS interfaces
- **Automatic refresh**: Daemon populates cache on configurable intervals
- **On-demand population**: Cache updates when users are accessed via daemon socket
- **Performance optimized**: Local file access instead of network calls

## Installation

```bash
make
sudo make install
```

## Testing with Sample Data

```bash
# Install sample cache files and test the module
sudo make install-samples
sudo make test
```

## Configuration

Add `nss_cache` to appropriate entries in `/etc/nsswitch.conf`:

```
passwd: files nss_cache
group:  files nss_cache
```

## Cache Files

The module reads from:
- `/var/cache/warp_portal/passwd.cache` - User information in passwd format
- `/var/cache/warp_portal/group.cache` - Group information in group format

These files are automatically managed by the Warp Portal daemon based on the cache configuration.

## Cache Format

### passwd.cache
Standard passwd format:
```
username:x:uid:gid:gecos:homedir:shell
```

### group.cache  
Standard group format:
```
groupname:x:gid:member1,member2,member3
```

## Daemon Integration

The daemon automatically:
1. Refreshes cache every X hours (configurable)
2. Adds users to cache when accessed via socket
3. Maintains cache consistency with upstream providers