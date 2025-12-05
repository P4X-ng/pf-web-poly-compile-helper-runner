# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024

### Added

- **pf Task Runner**: Symbol-free DSL for managing development workflows
  - Polyglot shell support for 40+ languages
  - Build system helpers (Make, CMake, Meson, Cargo, Go, Autotools, Just)
  - Parallel execution via SSH
  - Modular configuration with `include`
  - Parameter interpolation

- **REST API Server**: Build management via REST endpoints
  - Real-time WebSocket updates
  - Project and module management
  - Multi-language support (Rust, C, Fortran, WAT)

- **Automagic Builder**: Auto-detect project type and run appropriate build commands
  - Supports Rust, Go, Node.js, Python, Java/Maven, Java/Gradle, CMake, Meson, Make, Just, Autotools, Ninja

- **WebAssembly Compilation**: Multi-language WASM support
  - Rust via wasm-pack
  - C via Emscripten
  - Fortran via LFortran (experimental)
  - WAT via WABT

- **Container Infrastructure**: Podman-based development environment
  - Podman Quadlets for systemd integration
  - GPU support with CUDA
  - Build containers for Rust, C, Fortran
  - Debugger container with GDB, LLDB, pwndbg, radare2

- **Binary Injection & Debugging**: Advanced binary manipulation
  - Shared library compilation and injection
  - Function hooking and binary patching
  - WASM injection and assembly patching

- **LLVM Binary Lifting**: Binary-to-LLVM IR conversion
  - RetDec integration
  - McSema support
  - Cross-architecture targeting

- **Kernel Debugging**: Advanced security analysis
  - Automagic parse function detection
  - Complexity analysis
  - In-memory fuzzing
  - IOCTL detection

- **Web Security Testing**: Comprehensive vulnerability scanning
  - SQL injection, XSS, CSRF detection
  - Mass fuzzing capabilities
  - Security header checking

- **Interactive TUI**: Text-based user interface
  - Task organization by category
  - Interactive execution
  - Debugging tools integration

- **Package Manager Translation**: Cross-format package conversion
  - Supports deb, rpm, flatpak, snap, pacman
  - Hub-and-spoke model via .deb

- **Multi-Distro Container Management**: Lightweight containers for multiple Linux distributions
  - CentOS, Fedora, Arch, openSUSE support
  - Artifact extraction to host

- **ROP Exploit Demo**: Educational exploitation framework
  - Vulnerable binary examples
  - ROP chain generation
  - NX bypass demonstration

- **Git Cleanup Tools**: Large file removal from git history
  - Interactive TUI
  - Size analysis
  - Automatic backup

- **Playwright E2E Testing**: Browser automation tests for WASM validation

### Documentation

- Comprehensive README.md
- QUICKSTART.md guide
- REST API documentation
- Security testing guide
- Binary injection guide
- LLVM lifting guide
- Kernel debugging guide
- TUI documentation
- Package manager guide
