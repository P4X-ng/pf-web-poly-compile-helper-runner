# Build Helper Examples - Real World Usage

This directory contains examples demonstrating the build helper verbs.

## Example 1: C Project with Makefile

```bash
cd /tmp/test-build-helpers
pf test.pf build-with-make
```

## Example 2: CMake Project

```bash
cd /tmp/test-cmake
pf test.pf build-cmake
```

## Example 3: Auto-Detection

```bash
cd your-project
pf build-helper-demo  # Shows what build system is detected
```

## Example 4: LLVM IR Generation

```bash
pf c-llvm-demo      # Compile C to LLVM IR
pf cpp-llvm-demo    # Compile C++ to LLVM IR
```

## Example 5: Rust Project

```text
task cargo-release
  describe Build Rust project in release mode
  cargo build release=true
end

task cargo-test
  describe Run Rust tests
  cargo test
end
```

## Example 6: Go Project

```text
task go-build-static
  describe Build static Go binary
  go_build output=myapp ldflags="-s -w" tags=netgo
end
```

## Example 7: Complex Build Pipeline

```text
task full-build
  describe Complete build pipeline with detection
  build_detect
  shell if [ -f Makefile ]; then
  makefile clean all jobs=8
  shell elif [ -f CMakeLists.txt ]; then
  cmake . build_type=Release
  shell elif [ -f Cargo.toml ]; then
  cargo build release=true
  shell fi
end
```

## All Available Build Verbs

- `makefile [targets...] [jobs=N] [VAR=value...]` - Run make
- `cmake [source_dir] [build_dir=...] [build_type=...]` - CMake build
- `meson [source_dir] [build_dir=...] [buildtype=...]` - Meson build
- `cargo <subcommand> [release=true] [features=...]` - Rust/Cargo
- `go_build [subcommand=build] [output=...] [tags=...]` - Go build
- `configure [prefix=...] [opt=value...]` - Autotools configure
- `justfile [recipe] [args...]` - Just build
- `build_detect` - Auto-detect available build systems
