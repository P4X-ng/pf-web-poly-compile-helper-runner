#!/usr/bin/env bash
# Container-based installer for pf
# Builds the pf-runner image and installs a wrapper that runs pf via Docker/Podman.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="pf-runner:local"
BASE_IMAGE="localhost/pf-base:latest"
RUNTIME=""
WRAPPER_PATH="${HOME}/.local/bin/pf"
INSTALL_WRAPPER=1

usage() {
  cat <<'USAGE'
Usage: ./install.sh [--image NAME] [--runtime docker|podman] [--wrapper PATH] [--no-wrapper]

Builds the pf-runner container image (Dockerfile.pf-runner) and installs a small
wrapper that runs pf inside the container with your current working directory mounted.

Options:
  --image NAME       Image tag to build/use (default: pf-runner:local)
  --runtime NAME     Container runtime to use (auto-detects docker then podman)
  --wrapper PATH     Where to write the pf wrapper (default: ~/.local/bin/pf)
  --no-wrapper       Build image only, skip writing wrapper
  -h, --help         Show this help
USAGE
}

choose_runtime() {
  if [[ -n "${RUNTIME}" ]]; then
    if ! command -v "${RUNTIME}" >/dev/null 2>&1; then
      echo "Error: specified runtime '${RUNTIME}' not found" >&2
      exit 1
    fi
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
  else
    echo "Error: no container runtime found (install docker or podman)" >&2
    exit 1
  fi
}

build_image() {
  echo "[pf-install] Building image '${IMAGE_NAME}' with ${RUNTIME}..."
  ${RUNTIME} build -f "${ROOT_DIR}/containers/dockerfiles/Dockerfile.pf-runner" -t "${IMAGE_NAME}" "${ROOT_DIR}"
  echo "[pf-install] Image built: ${IMAGE_NAME}"
}

build_base_image() {
  echo "[pf-install] Building base image '${BASE_IMAGE}' with ${RUNTIME}..."
  ${RUNTIME} build -f "${ROOT_DIR}/containers/dockerfiles/Dockerfile.base" -t "${BASE_IMAGE}" "${ROOT_DIR}"
  echo "[pf-install] Base image built: ${BASE_IMAGE}"
}

write_wrapper() {
  local target="${WRAPPER_PATH}"
  mkdir -p "$(dirname "${target}")"
  cat > "${target}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DEFAULT_IMAGE="__DEFAULT_IMAGE__"
DEFAULT_RUNTIME="__DEFAULT_RUNTIME__"
IMAGE="${PF_IMAGE:-$DEFAULT_IMAGE}"
RUNTIME="${PF_RUNTIME:-$DEFAULT_RUNTIME}"

if ! command -v "$RUNTIME" >/dev/null 2>&1; then
  echo "Error: container runtime '$RUNTIME' not found. Set PF_RUNTIME or install docker/podman." >&2
  exit 1
fi

WORKDIR="${PWD}"
ARGS=(run --rm)
if [[ -t 0 && -t 1 ]]; then
  ARGS+=(-it)
fi
USER_FLAG=()
if command -v id >/dev/null 2>&1; then
  USER_FLAG=(--user "$(id -u)":"$(id -g)")
fi
ARGS+=(-v "${WORKDIR}:${WORKDIR}")
ARGS+=(-w "${WORKDIR}")
if [[ -d "${HOME}" ]]; then
  ARGS+=(-v "${HOME}:${HOME}")
  ARGS+=(-e "HOME=${HOME}")
fi

# Expose host podman into the container when present (for container/quadlet tasks)
# Mount podman binary and runtime socket so 'podman' inside the container talks to host daemon
if command -v podman >/dev/null 2>&1; then
  # binary
  if [[ -x "/usr/bin/podman" ]]; then
    ARGS+=(-v "/usr/bin/podman:/usr/bin/podman:ro")
  fi
  # helpers
  [[ -d "/usr/libexec/podman" ]] && ARGS+=(-v "/usr/libexec/podman:/usr/libexec/podman:ro")
  [[ -d "/usr/lib/podman" ]] && ARGS+=(-v "/usr/lib/podman:/usr/lib/podman:ro")
  # socket (rootless)
  SOCK_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  if [[ -S "${SOCK_DIR}/podman/podman.sock" ]]; then
    ARGS+=(-v "${SOCK_DIR}/podman:${SOCK_DIR}/podman")
    # ensure same path inside container
    ARGS+=(-e "XDG_RUNTIME_DIR=${SOCK_DIR}")
    ARGS+=(-e "CONTAINER_HOST=unix://${SOCK_DIR}/podman/podman.sock")
  fi
  # config
  [[ -d "/etc/containers" ]] && ARGS+=(-v "/etc/containers:/etc/containers:ro")
  [[ -d "/usr/share/containers" ]] && ARGS+=(-v "/usr/share/containers:/usr/share/containers:ro")
fi

ARGS+=(-e "PFY_FILE=${PFY_FILE:-}")

exec "$RUNTIME" "${ARGS[@]}" "${USER_FLAG[@]}" "$IMAGE" pf "$@"
EOF
  # bake defaults
  sed -i "s|__DEFAULT_IMAGE__|${IMAGE_NAME}|g" "${target}"
  sed -i "s|__DEFAULT_RUNTIME__|${RUNTIME}|g" "${target}"
  chmod +x "${target}"
  echo "[pf-install] Wrapper installed at ${target}"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE_NAME="$2"; shift 2;;
    --runtime)
      RUNTIME="$2"; shift 2;;
    --wrapper)
      WRAPPER_PATH="$2"; shift 2;;
    --no-wrapper)
      INSTALL_WRAPPER=0; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

choose_runtime
build_base_image
build_image

if [[ ${INSTALL_WRAPPER} -eq 1 ]]; then
  write_wrapper
  echo "[pf-install] Add $(dirname "${WRAPPER_PATH}") to PATH if needed."
  echo "[pf-install] Run 'pf list' to verify."
else
  echo "[pf-install] Wrapper skipped (image only)."
fi

exit 0
