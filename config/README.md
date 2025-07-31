# Warp Portal Configuration Templates

This directory contains sample configuration files for the Warp Portal system.

## Available Configuration Templates

### `config.yaml` (Default)
The default configuration template using file-based user/group management. This is installed by default during system installation.

**Usage:**
- Copied to `/etc/warp_portal/config.yaml` during installation
- Edit users, SSH keys, and sudo permissions directly in the file
- Suitable for small to medium deployments

### `config.file.yaml` 
Same as `config.yaml` - file-based configuration with all user data stored locally.

### `config.http.yaml`
Configuration template for HTTP-based user/group management.

**Usage:**
- Copy to `/etc/warp_portal/config.yaml` to use HTTP provider
- Configure API endpoint and authentication
- Enables automatic machine registration via `warpportal register` CLI
- Suitable for large deployments with centralized user management

### `env.config.yaml`
Configuration template showing environment variable usage for sensitive values.

**Usage:**
- Copy to `/etc/warp_portal/config.yaml` to use environment-based config
- Set environment variables for API tokens, URLs, etc.
- Suitable for containerized deployments

## Installation

During system installation, `config.yaml` is automatically copied to `/etc/warp_portal/config.yaml`.

To use a different template:

```bash
# Switch to HTTP-based configuration
sudo cp /path/to/warp-portal/config/config.http.yaml /etc/warp_portal/config.yaml

# Switch to environment-based configuration  
sudo cp /path/to/warp-portal/config/env.config.yaml /etc/warp_portal/config.yaml

# Restart daemon to pick up changes
sudo systemctl restart warp_portal_daemon
```

## Configuration Reference

See the main project README for detailed configuration options and examples.