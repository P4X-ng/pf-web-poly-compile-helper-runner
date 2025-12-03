# Containers Directory

This directory contains all containerization files for the polyglot development environment.

## Structure

- `web-services/` - API server and web interface containers
- `build-environment/` - Compilation toolchains for Rust, C, Fortran, WAT
- `security-tools/` - Debugging and reverse engineering tools
- `development/` - pf-runner and development environment
- `base/` - Common base images and shared components
- `dockerfiles/` - All Dockerfile definitions
- `scripts/` - Container build and management scripts
- `quadlets/` - Podman Quadlet files for systemd integration

## Automatic Containerization

The pf-runner includes an automatic containerization module (`pf_containerize.py`) that can:

1. **Detect project type** - Automatically identify programming languages and build systems
2. **Generate Dockerfiles** - Create optimized Dockerfiles based on project detection
3. **Generate Quadlet files** - Create systemd service files for Podman
4. **Build with retry** - Automatically retry failed builds with error pattern matching

### Quick Start

```bash
# Auto-containerize the current project
pf containerize

# Generate Dockerfile only (no build)
pf containerize dockerfile_only=true

# Containerize with hints
pf containerize install_deps="libssl-dev" main_bin="./build/app" port=8080

# Build with retry and then containerize
pf ci-containerize image=myapp tag=v1.0.0
```

### Supported Languages and Build Systems

| Language | Build System | Detection File |
|----------|-------------|----------------|
| Rust | Cargo | `Cargo.toml` |
| Go | Go Modules | `go.mod` |
| Node.js | npm/yarn/pnpm | `package.json` |
| Python | pip/poetry/pipenv | `requirements.txt`, `pyproject.toml` |
| C/C++ | CMake | `CMakeLists.txt` |
| C/C++ | Make | `Makefile` |
| C/C++ | Meson | `meson.build` |
| Java | Maven | `pom.xml` |
| Java | Gradle | `build.gradle` |

### User Hints

When automatic detection isn't enough, you can provide hints:

- `--install-hint-deps="apt packages"` - Additional system packages to install
- `--main-bin-hint="path/to/binary"` - Main executable path
- `--port-hint=8080` - Port to expose
- `--base-image-hint="image:tag"` - Base Docker image to use
- `--build-commands-hint="make && make install"` - Custom build commands

### Retry Mechanism

The `autobuild_retry` command includes automatic error recovery:

```bash
# Basic retry with defaults (3 retries, exponential backoff)
pf autobuild_retry

# Custom retry configuration
pf autobuild_retry max_retries=5 initial_delay=2 max_delay=60
```

Error patterns automatically detected and fixed:
- Missing apt packages
- Missing Python/Node modules
- Permission denied errors
- Network timeouts
- Missing lock files (Cargo.lock, go.sum)

## Traditional Container Usage

Each subdirectory contains:
- `Dockerfile` - Container definition
- `entrypoint.sh` - Container startup script
- `README.md` - Service-specific documentation
- Configuration files as needed

### Building Containers

```bash
# Build all container images
./containers/scripts/build-containers.sh all

# Build specific components
./containers/scripts/build-containers.sh base
./containers/scripts/build-containers.sh api
./containers/scripts/build-containers.sh build
./containers/scripts/build-containers.sh debug
```

### Using Quadlets (Systemd Integration)

Quadlet files in `quadlets/` enable systemd-native container management:

```bash
# Install quadlet files
./containers/scripts/install-quadlets.sh --install

# Start services
systemctl --user start pf-main-pod

# View logs
journalctl --user -u pf-web-service -f
```

See the main README.md for complete setup instructions.