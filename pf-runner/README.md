# pf — tiny Fabric runner (symbol-free DSL)

INSTALL

make setup # (creates ./pf symlink)
make install-local # (creates symlink in ~/.local/bin

That's it!


## WHAT IS IT!?

Single-file **Fabric** runner with a tiny, readable DSL, parallel SSH, and live output.

- One file: `pf.py`
- Symbol-free DSL: `shell`, `packages install/remove`, `service start/stop/enable/disable/restart`, `directory`, `copy`
- Task metadata: `describe` shows in `pf list`
- Project split: `include` other `.pf` files from `Pfyfile.pf`
- Per-task params: `pf run-tls tls_cert=... port=9443` → use `$tls_cert`, `$port` in DSL
- **Per-task env**: line `env KEY=VAL KEY2=VAL2` applies to the rest of the task
- Host args: `env=prod`, `hosts=user@ip:port,...`, repeatable `host=...`

## Install

```bash
pip install "fabric>=3.2,<4"
chmod +x pf.py
```

## Quickstart

```bash
pf list
pf env=prod update
pf hosts=ubuntu@10.0.0.5:22,punk@10.4.4.4:24 run-tls tls_cert=$PWD/certs/server.crt tls_key=$PWD/certs/server.key port=9443
```

## Toolchain setup

If you're on an apt-based host and want the polyglot `shell` templates to "just work", run:

```bash
pf setup
```

That installs Java/OpenJDK 25, Google Android build tools (34.0.0), Go, LLVM/clang, Ninja and gfortran. Extra interpreters (LuaJIT, static zsh, ch) plus `rustup` live under a separate opt-in task:

```bash
pf setup-optional
```

Feel free to tweak the package list if your distro uses different names or you want to pin versions.

## DSL

```text
task run-tls
  describe Start packetfs-infinity with Hypercorn TLS
  env tls_cert=$PWD/certs/server.crt tls_key=$PWD/certs/server.key port=9443
  shell podman run --rm \
       -p $port:9443 \
       -v $tls_cert:/certs/server.crt:ro \
       -v $tls_key:/certs/server.key:ro \
       packetfs/pfs-infinity:latest
end
```

- `$VAR` / `${VAR}` are interpolated from (in order): **task params** → **task env** → **process env**.
- On remote hosts: `env` is translated to `export VAR=...;` before each command.
- Locally: variables are provided via the process environment.

### Polyglot `shell` overrides

The `shell` verb now accepts a shebang-style inline template to pipe snippets through many common runtimes:

```text
task demo
  shell [lang:python] print("hello from python")
  shell [lang:rust] @scripts/demo.rs -- --flag fast
  shell [lang:java-android] @scripts/android_smoke/Main.java -- --device pixel_8
end
```

You can also pin a language across multiple lines without repeating the inline tag:

```text
task multi
  shell_lang python
  shell print("first")
  shell print("second")
  shell_lang default   # back to whatever the task inherited
  shell echo "done"
end
```

Place `#!lang:python` (or `#!lang:fish`) at the very top of a Pfyfile to set a repository-default language; `shell_lang none` clears the override inside a task.

- Prefix the inline template with `lang:` / `language:` / `polyglot` plus the language name.
- Short snippets can be written inline; for multiline programs use `@path/to/file.ext`.
- `@file -- arg1 arg2` lets you pass CLI args to the generated program.
- All snippets run inside ephemeral temp directories via `mktemp`; artifacts are deleted unless the command fails.
- Supported names (aliases in parentheses): `python (py, python3)`, `bash`, `sh`, `zsh`, `fish`, `lua`, `go (golang)`, `c (clang)`, `c++ (cpp, cxx, clang++)`, `fortran (gfortran, fortran90)`, `asm (asm86)`, `rust`, `swift`, `java-openjdk (java)`, `java-android (java-android-google, android-java)`.
- Officially supported languages remain **python**, **bash**, and **fish**. Using `shell_lang python` / `shell_lang bash` / `shell_lang fish` (or a `#!lang:...` header) ensures those runtimes stay active until you reset or clear them. Everything else is best-effort and simply stitches together available interpreters/compilers (`clang/clang++`, `gfortran`, `go`, `rustc`, `swift`, `javac`, Android SDK `d8`/`dalvikvm`, etc.). Install the toolchains you care about or expect the command to fail loudly.
- `java-android` looks for `ANDROID_SDK_ROOT`/`ANDROID_HOME` plus build-tools (`d8`) and `dalvikvm`. If those aren’t present it falls back to running on the local JVM after compiling against whatever `android.jar` it can find.

Because the snippets expand to real shell scripts, they inherit your `sudo=true`/remote host settings and obey per-task `env` just like regular `shell` lines. Treat this as a "test test runner" sandbox — there are zero safety guarantees when mixing exotic interpreters.

### LLVM IR Output

C, C++, and Fortran can emit LLVM IR instead of executing:

```text
task show-llvm
  shell [lang:c-llvm] int main() { return 42; }
  shell [lang:cpp-llvm] int main() { return 42; }
  shell [lang:fortran-llvm] program hello; end program hello
end
```

Available LLVM variants:
- `c-llvm` / `c-ir` / `c-ll` - C to LLVM IR (text format)
- `cpp-llvm` / `cpp-ir` / `cpp-ll` - C++ to LLVM IR
- `c-llvm-bc` / `c-bc` - C to LLVM bitcode (then disassembled to IR)
- `cpp-llvm-bc` / `cpp-bc` - C++ to LLVM bitcode
- `fortran-llvm` / `fortran-ir` / `fortran-ll` - Fortran to LLVM IR (requires flang)

### Build System Helpers

The DSL includes dedicated verbs for common build systems. Use `build_detect` to analyze your project:

```text
task detect
  describe Auto-detect build system
  build_detect
end
```

#### Automagic Builder 🪄

**NEW!** The `autobuild` verb automatically detects your project's build system and runs the appropriate build command with zero configuration:

```text
task quick-build
  describe Build any project automatically
  autobuild
end

task release-build
  describe Release build with auto-detection
  autobuild release=true jobs=8
end

task monorepo-build
  describe Build multiple modules
  autobuild dir=./frontend
  autobuild dir=./backend
  autobuild dir=./shared
end
```

**Supported Build Systems (in priority order):**
1. **Cargo** (Cargo.toml) → `cargo build`
2. **Go** (go.mod) → `go build`
3. **npm** (package.json) → `npm run build` or `npm install`
4. **Python** (setup.py, pyproject.toml) → `pip install -e .` or `python setup.py build`
5. **Maven** (pom.xml) → `mvn compile`
6. **Gradle** (build.gradle) → `gradle build`
7. **CMake** (CMakeLists.txt) → `cmake` + `cmake --build`
8. **Meson** (meson.build) → `meson setup` + `meson compile`
9. **Just** (justfile) → `just`
10. **Autotools** (configure) → `./configure` + `make`
11. **Make** (Makefile) → `make`
12. **Ninja** (build.ninja) → `ninja`

**Parameters:**
- `release=true` - Build in release/optimized mode
- `jobs=N` - Number of parallel jobs (default: 4)
- `dir=<path>` - Build a specific subdirectory
- `target=<target>` - Custom build target (for Make, etc.)

The automagic builder prioritizes specific build systems over generic ones (e.g., CMake over generated Makefiles), ensuring the "source of truth" build system is always used.

#### Makefile

```text
task build
  describe Build with make
  makefile all jobs=4
end

task rebuild
  describe Clean and rebuild
  makefile clean all verbose=true
end
```

Options: `jobs=N`, `parallel=true`, `verbose=true`, plus any `VAR=value` make variables.

#### CMake

```text
task cmake-build
  describe Configure and build with CMake
  cmake . build_dir=build build_type=Release
end
```

Options: `build_dir=<path>`, `build_type=<Debug|Release|...>`, `generator=<Ninja|...>`, `target=<name>`, `jobs=N`, plus any `-D` CMake options as `OPTION=value`.

#### Meson + Ninja

```text
task meson-build
  describe Build with Meson
  meson . build_dir=builddir buildtype=release
end
```

Options: `build_dir=<path>`, `buildtype=<debug|release|...>`, `target=<name>`, plus any `-D` Meson options.

#### Cargo (Rust)

```text
task cargo-build
  describe Build Rust project
  cargo build release=true
end

task cargo-test
  describe Run tests
  cargo test
end
```

Options: `release=true`, `features=<list>`, `target=<triple>`, `manifest_path=<path>`, plus any cargo flags.

#### Go

```text
task go-build
  describe Build Go binary
  go_build output=myapp tags=netgo
end

task go-test
  describe Run Go tests
  go_build subcommand=test race=true
end
```

Options: `subcommand=<build|test|...>`, `output=<path>`, `tags=<list>`, `race=true`, `ldflags=<flags>`.

#### Autotools (Configure)

```text
task configure
  describe Run configure script
  configure prefix=/usr/local shared=true ssl=true
end
```

Options: `prefix=<path>`, `<feature>=true` → `--enable-<feature>`, `<feature>=false` → `--disable-<feature>`, `<opt>=<value>` → `--<opt>=<value>`.

#### Just

```text
task just-build
  describe Run justfile recipe
  justfile build --verbose
end
```

All arguments are passed directly to the `just` command.

## Includes

Top-level in `Pfyfile.pf`:

```text
include "base.pf"
include web.pf
```

## Environments & Hosts

```bash
pf env=prod update
pf env=prod env=staging run
pf hosts=ubuntu@10.0.0.5:22,punk@10.4.4.4:24 down
pf host=ubuntu@10.0.0.5:22 sudo=true upgrade
```

Define env aliases in `ENV_MAP` at the top of `pf.py`:

```python
ENV_MAP = {
  "local": ["@local"],
  "prod": ["ubuntu@10.0.0.5:22", "punk@10.4.4.4:24"],
  "staging": "staging@10.1.2.3:22,staging@10.1.2.4:22",
}
```

## Project Structure

This project uses a modular task organization:

- `Pfyfile.pf` - Main configuration with includes for all task categories
- `Pfyfile.dev.pf` - Development tasks (setup, lint, test, symlink)
- `Pfyfile.tests.pf` - Testing tasks (basic, integration, docs)
- `Pfyfile.builds.pf` - Build and release tasks (validate, package, install)
- `Pfyfile.cleanup.pf` - Cleanup and maintenance tasks
- `base.pf`, `web.pf`, `test.pf` - Core functionality examples
- `scripts/` - Helper scripts (following no-long-commands rule)

## Quick Start Commands

```bash
# Complete project setup
./pf.py setup

# Validate everything works
./pf.py validate

# Run basic functionality tests
./pf.py test-basic

# Clean up project
./pf.py clean-all
```

## Notes

- Uses your SSH agent/keys and `~/.ssh/config` if present
- `packages` assumes **apt**; easy to extend to `dnf`, `pacman`, etc.
- Parallelism: min(32, number of hosts). Tweak in code.
- Follows PODMAN > Docker rule - use `podman_install` instead of `docker_install`
- Helper scripts in `scripts/` directory keep pf files clean and readable


## Polyglot languages (native-linux target)

**Built-in runtimes** via `shell [lang:...]` or `shell_lang ...`:

- asm, bash, c, cpp, crystal, dart, dash, deno, elixir, fish, fortran, go, haskell, haskell-compile, java-android, java-openjdk, julia, ksh, lua, nim, node, ocaml, ocamlc, perl, php, pwsh, python, r, ruby, rust, sh, tcsh, ts-node, zig, zsh

**Aliases** (map → canonical):

- `shell` → `bash`
- `sh` → `sh`
- `zshell` → `zsh`
- `powershell` → `pwsh`
- `ps1` → `pwsh`
- `py` → `python`
- `python3` → `python`
- `ipython` → `python`
- `javascript` → `node`
- `js` → `node`
- `nodejs` → `node`
- `ts` → `deno`
- `typescript` → `deno`
- `tsnode` → `ts-node`
- `c++` → `cpp`
- `cxx` → `cpp`
- `clang` → `c`
- `clang++` → `cpp`
- `g++` → `cpp`
- `gcc` → `c`
- `golang` → `go`
- `rb` → `ruby`
- `pl` → `perl`
- `ml` → `ocaml`
- `hs` → `haskell`
- `fortran90` → `fortran`
- `gfortran` → `fortran`
- `java` → `java-openjdk`
- `java-openjdk` → `java-openjdk`
- `java-android-google` → `java-android`
- `java-android` → `java-android`
- `android-java` → `java-android`
- `fishshell` → `fish`
- `shellscript` → `bash`
- `dashshell` → `dash`