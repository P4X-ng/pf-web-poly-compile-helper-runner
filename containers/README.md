# Container Infrastructure with Podman Quadlets

This project provides a complete containerized development environment using Podman, with support for both standard containers and systemd-integrated Quadlets.

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture Overview](#-architecture-overview)
- [Container Images](#-container-images)
- [Podman Compose](#-podman-compose)
- [Quadlet Files](#-quadlet-files)
- [GPU Support](#-gpu-support)
- [Debugging Guide](#-debugging-guide)
- [Troubleshooting](#-troubleshooting)

## 🚀 Quick Start

### Prerequisites

- **Podman 4.4+** (with quadlet support)
- **podman-compose** (optional, for compose workflow)
- **nvidia-container-toolkit** (optional, for GPU support)

### Option 1: Using Podman Compose (Recommended for Development)

```bash
# Build all container images
./containers/scripts/build-containers.sh

# Start the API server
podman-compose up -d api-server

# Build all WASM modules
podman-compose up build-rust build-c build-fortran build-wat

# Open a debugging shell
podman-compose run --rm -it debugger
```

### Option 2: Using Quadlets (Recommended for Production)

```bash
# Build images first
./containers/scripts/build-containers.sh

# Install quadlet files
./containers/scripts/install-quadlets.sh

# Start services via systemd
systemctl --user daemon-reload
systemctl --user start pf-api-server

# Enable on boot
systemctl --user enable pf-api-server
```

### Option 3: Development Workflow Script

```bash
# Start development server
./containers/scripts/run-dev.sh

# Build all WASM
./containers/scripts/run-dev.sh build

# Open debugger shell
./containers/scripts/run-dev.sh debug

# View status
./containers/scripts/run-dev.sh status
```

## 🏗️ Architecture Overview

The containerized environment is organized into logical service groups (pods):

```
┌─────────────────────────────────────────────────────────────┐
│                     pf-web Network                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────────┐    │
│  │   API Services Pod  │    │    Build Services Pod   │    │
│  │                     │    │                         │    │
│  │  ┌───────────────┐  │    │  ┌─────────────────┐   │    │
│  │  │  api-server   │  │    │  │   build-rust    │   │    │
│  │  │  (Node.js)    │  │    │  │   (wasm-pack)   │   │    │
│  │  └───────────────┘  │    │  └─────────────────┘   │    │
│  │                     │    │                         │    │
│  │  ┌───────────────┐  │    │  ┌─────────────────┐   │    │
│  │  │  pf-runner    │  │    │  │    build-c      │   │    │
│  │  │  (Python)     │  │    │  │  (Emscripten)   │   │    │
│  │  └───────────────┘  │    │  └─────────────────┘   │    │
│  │                     │    │                         │    │
│  └─────────────────────┘    │  ┌─────────────────┐   │    │
│                              │  │  build-fortran  │   │    │
│  ┌─────────────────────┐    │  │   (LFortran)    │   │    │
│  │  Debugging Pod      │    │  └─────────────────┘   │    │
│  │                     │    │                         │    │
│  │  ┌───────────────┐  │    └─────────────────────────┘    │
│  │  │   debugger    │  │                                   │
│  │  │  (GDB/LLDB)   │  │                                   │
│  │  └───────────────┘  │    ┌─────────────────────────┐    │
│  │                     │    │     Shared Volumes      │    │
│  │  ┌───────────────┐  │    │                         │    │
│  │  │ debugger-gpu  │  │    │  • pf-wasm-output      │    │
│  │  │  (CUDA)       │  │    │  • pf-project-src      │    │
│  │  └───────────────┘  │    │                         │    │
│  └─────────────────────┘    └─────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Container Images

All images are based on **Ubuntu 24.04** and include essential debugging tools.

| Image | Description | Size (approx) |
|-------|-------------|---------------|
| `pf-base` | Base image with common tools | ~500MB |
| `pf-runner` | pf task runner (Python/Fabric) | ~600MB |
| `pf-api-server` | Node.js REST API server | ~800MB |
| `pf-build-rust` | Rust + wasm-pack | ~1.5GB |
| `pf-build-c` | Emscripten toolchain | ~2GB |
| `pf-build-fortran` | LFortran compiler | ~1.2GB |
| `pf-debugger` | Full debugging suite | ~2.5GB |
| `pf-debugger-gpu` | GPU-enabled debugger | ~4GB |

### Building Images

```bash
# Build all images
./containers/scripts/build-containers.sh

# Build specific groups
./containers/scripts/build-containers.sh base    # Base only
./containers/scripts/build-containers.sh api     # API services
./containers/scripts/build-containers.sh build   # Build tools
./containers/scripts/build-containers.sh debug   # Debuggers

# Build without cache
./containers/scripts/build-containers.sh --no-cache all
```

## 🐳 Podman Compose

The `podman-compose.yml` file provides a complete development environment.

### Common Commands

```bash
# Start API server
podman-compose up -d api-server

# Build WASM modules
podman-compose up build-rust build-c build-fortran build-wat

# View logs
podman-compose logs -f api-server

# Open debugging shell
podman-compose run --rm -it debugger

# Stop everything
podman-compose down

# Clean up volumes
podman-compose down -v
```

### Services

| Service | Description | Ports |
|---------|-------------|-------|
| `api-server` | REST API + WebSocket server | 8080 |
| `pf-runner` | pf task runner | - |
| `build-rust` | Rust WASM compilation | - |
| `build-c` | C WASM compilation | - |
| `build-fortran` | Fortran WASM compilation | - |
| `build-wat` | WAT to WASM assembly | - |
| `debugger` | Debugging tools | - |
| `debugger-gpu` | GPU debugging (profile: gpu) | - |

### GPU Support

To use GPU-accelerated features:

```bash
# Start GPU debugger (requires nvidia-container-toolkit)
podman-compose --profile gpu up -d debugger-gpu

# Or run interactively
podman-compose --profile gpu run --rm -it debugger-gpu
```

## 📄 Quadlet Files

Quadlets are systemd-native container definitions that enable seamless integration with systemd services.

### File Types

| Extension | Purpose |
|-----------|---------|
| `.container` | Container definitions |
| `.pod` | Pod (container group) definitions |
| `.network` | Network definitions |
| `.volume` | Volume definitions |

### Installation

```bash
# Install for current user
./containers/scripts/install-quadlets.sh

# Install system-wide (requires root)
sudo ./containers/scripts/install-quadlets.sh

# Remove installed quadlets
./containers/scripts/install-quadlets.sh --remove

# Check status
./containers/scripts/install-quadlets.sh --status
```

### Managing Services

After installing quadlets:

```bash
# Reload systemd
systemctl --user daemon-reload

# Start services
systemctl --user start pf-api-server
systemctl --user start pf-web-api-pod  # Start entire pod

# Check status
systemctl --user status pf-api-server

# View logs
journalctl --user -u pf-api-server -f

# Enable at login
systemctl --user enable pf-api-server
```

### Quadlet File Locations

- **User**: `~/.config/containers/systemd/`
- **System**: `/etc/containers/systemd/`

## 🎮 GPU Support

For GPU-accelerated workloads (CUDA, machine learning, etc.):

### Prerequisites

1. **NVIDIA Driver** installed on host
2. **nvidia-container-toolkit** installed:

```bash
# Ubuntu/Debian
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
```

### Using GPU Containers

```bash
# With podman-compose
podman-compose --profile gpu up -d debugger-gpu

# Or directly with podman
podman run --rm -it --device nvidia.com/gpu=all localhost/pf-debugger-gpu:latest

# Verify GPU access
podman run --rm localhost/pf-debugger-gpu:latest nvidia-smi
```

## 🐛 Debugging Guide

The debugging container includes:

- **GDB** with pwndbg extension
- **LLDB** for LLVM-based debugging
- **Radare2** for reverse engineering
- **Binary analysis tools** (binutils, binwalk, patchelf)
- **Python tools** (capstone, keystone, unicorn, angr)
- **Network tools** (tcpdump, tshark, socat)

### Quick Debugging Session

```bash
# Start debugger
./containers/scripts/run-dev.sh debug

# Inside container:
# Run GDB with pwndbg
gdb ./your-binary

# Use radare2
r2 ./your-binary

# Analyze binary
checksec --file=./your-binary
```

### Debugging a Binary

```bash
# Mount your binary directory
podman run --rm -it \
  -v ./my-binaries:/workspace:rw \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  localhost/pf-debugger:latest

# Inside container
cd /workspace
gdb ./my-program
```

## 🔧 Troubleshooting

### Container Build Fails

```bash
# Check podman version
podman --version  # Should be 4.4+

# Build with verbose output
podman build --progress=plain -t pf-base -f containers/dockerfiles/Dockerfile.base .
```

### Quadlets Not Working

```bash
# Check systemd generator
/usr/lib/systemd/user-generators/podman-user-generator --user --debug

# View generated units
systemctl --user cat pf-api-server

# Check for errors
journalctl --user -u pf-api-server --since "5 minutes ago"
```

### Permission Issues

```bash
# Fix volume permissions
podman unshare chown -R $(id -u):$(id -g) ./data

# Run rootless podman
podman system migrate
```

### Network Issues

```bash
# Recreate network
podman network rm pf-web
podman network create pf-web

# Check network
podman network inspect pf-web
```

### GPU Not Detected

```bash
# Verify nvidia-container-toolkit
nvidia-ctk cdi list

# Generate CDI spec
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml

# Test GPU access
podman run --rm --device nvidia.com/gpu=all ubuntu nvidia-smi
```

## 📁 Directory Structure

```
containers/
├── dockerfiles/
│   ├── Dockerfile.base          # Base Ubuntu 24.04 image
│   ├── Dockerfile.pf-runner     # pf task runner
│   ├── Dockerfile.api-server    # Node.js API server
│   ├── Dockerfile.build-rust    # Rust WASM builder
│   ├── Dockerfile.build-c       # C/Emscripten builder
│   ├── Dockerfile.build-fortran # Fortran builder
│   ├── Dockerfile.debugger      # Debugging tools
│   └── Dockerfile.debugger-gpu  # GPU-enabled debugger
├── quadlets/
│   ├── pf-web.network           # Shared network
│   ├── pf-wasm-output.volume    # Output volume
│   ├── pf-project-src.volume    # Source volume
│   ├── pf-web-api.pod           # API services pod
│   ├── pf-web-build.pod         # Build services pod
│   ├── pf-debugger.pod          # Debugging pod
│   ├── pf-runner.container      # pf-runner container
│   ├── pf-api-server.container  # API server container
│   ├── pf-build-*.container     # Build containers
│   └── pf-debugger*.container   # Debugger containers
├── scripts/
│   ├── build-containers.sh      # Build all images
│   ├── install-quadlets.sh      # Install quadlet files
│   └── run-dev.sh               # Development workflow
└── README.md                    # This file

podman-compose.yml               # Compose file for development
```

## 🔗 Related Documentation

- [pf-runner Documentation](../pf-runner/README.md)
- [API Server Guide](../docs/REST-API.md)
- [Debugging Guide](../demos/debugging/README.md)
- [Podman Quadlet Documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
