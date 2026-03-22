## Development
```bash
# Run tests
make test

# Lint
make lint

# Build
make build

# Build, test, and lint
make all
```

## Building ISO Locally
To build the ISO locally (requires Docker):

```bash
# Build the OS container image
docker build . --build-arg VERSION=dev -t firewall4ai:dev

# Export and create ISO
docker create --name export firewall4ai:dev
mkdir rootfs && docker export export | tar -x -C rootfs && docker rm export
sudo ./rootfs/usr/bin/elemental --debug build-iso --bootloader-in-rootfs --extra-cmdline "" dir:rootfs
```

This produces `elemental.iso` which can be used to install Firewall4AI on bare metal or VMs.

## Upgrading an Existing Installation
After a new version is released:
```bash
elemental upgrade --reboot --system oci:ghcr.io/olljanat-ai/firewall4ai:<version>
```

## Release
Releases are automated via GitHub Actions. To create a release:
```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds the Debian 13 OS image with Elemental Toolkit, pushes it to GHCR, creates a bootable ISO, and publishes a GitHub release.
