# Warp Portal Repository

This repository contains multiple components, including:

- **daemon**: The main Go application.
- **nss**: A custom NSS module written in C.
- **pam**: Placeholder for PAM-related modules.

## Prerequisites

Before using this repository, ensure you have the following installed:

- **Git**: To clone the repository.

  ```bash
  sudo apt update
  sudo apt install git
  ```

- **Build tools**: Required for compiling the components.

  ```bash
  sudo apt install build-essential gcc pkg-config
  ```

## Cloning the Repository

Clone the repository to your local machine:

```bash
git clone <repository-url>
cd warp-portal
```

## Building and Installing Components

Each folder contains a `Makefile` to build and install its respective components. Navigate to the desired folder and run the `Makefile` commands.

### Example: Building and Installing the NSS Module

1. Navigate to the `nss` directory:

   ```bash
   cd nss
   ```

2. Build the module:

   ```bash
   make
   ```

3. Install the module:

   ```bash
   sudo make install
   ```

Repeat similar steps for other components like `daemon` or `pam` by navigating to their respective directories and running the `Makefile` commands.

## Uninstalling the NSS Module

To uninstall the NSS module:

```bash
sudo make uninstall
```

## Debugging

To build the NSS module with debugging enabled:

```bash
make debug
```

## Testing Dependencies

To check if all dependencies are installed:

```bash
make test-deps
```

## Notes

- The `INSTALL_DIR` for the NSS module is determined dynamically based on your system architecture.
- Ensure you have `sudo` privileges for installation and configuration steps.

This guide applies to both Debian and Ubuntu systems.
