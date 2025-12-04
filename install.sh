#!/usr/bin/env bash
# Container-based installer for pf
# Builds the pf-runner image and installs the pf executable directly to /usr/local/bin.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="pf-runner:local"
BASE_IMAGE="localhost/pf-base:latest"
RUNTIME=""

usage() {
  cat <<'USAGE'
Usage: ./install.sh [--image NAME] [--runtime docker|podman]

Builds the pf-runner container image (Dockerfile.pf-runner) and installs the pf
executable directly to /usr/local/bin using a privileged container with mounted volume.

Options:
  --image NAME       Image tag to build/use (default: pf-runner:local)
  --runtime NAME     Container runtime to use (auto-detects docker then podman)
  -h, --help         Show this help

Note: This installation requires sudo privileges to write to /usr/local/bin.
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

install_executable() {
  echo "[pf-install] Installing pf executable to /usr/local/bin..."
  
  # Check if we can write to /usr/local/bin
  if [[ ! -w /usr/local/bin ]] && [[ $EUID -ne 0 ]]; then
    echo "[pf-install] Warning: /usr/local/bin is not writable. You may need sudo privileges."
    echo "[pf-install] Attempting installation with sudo..."
    SUDO_CMD="sudo"
  else
    SUDO_CMD=""
  fi
  
  # Create a temporary container to extract the executable
  echo "[pf-install] Extracting pf executable from container..."
  TEMP_CONTAINER=$(${RUNTIME} create "${IMAGE_NAME}")
  
  # Copy the main Python script from the container
  if ! ${RUNTIME} cp "${TEMP_CONTAINER}:/app/pf-runner/pf_parser.py" /tmp/pf_parser.py; then
    echo "Error: Failed to extract pf_parser.py from container" >&2
    ${RUNTIME} rm "${TEMP_CONTAINER}" >/dev/null 2>&1 || true
    exit 1
  fi
  
  # Clean up the temporary container
  ${RUNTIME} rm "${TEMP_CONTAINER}" >/dev/null 2>&1 || true
  
  # Create a proper executable script with shebang
  cat > /tmp/pf-executable << 'EOF'
#!/usr/bin/env python3
EOF
  
  # Append the Python script content (skip the first line if it's a comment)
  tail -n +2 /tmp/pf_parser.py >> /tmp/pf-executable
  
  # Install the executable
  if [[ -n "${SUDO_CMD}" ]]; then
    ${SUDO_CMD} cp /tmp/pf-executable /usr/local/bin/pf
    ${SUDO_CMD} chmod +x /usr/local/bin/pf
    ${SUDO_CMD} chown root:root /usr/local/bin/pf
  else
    cp /tmp/pf-executable /usr/local/bin/pf
    chmod +x /usr/local/bin/pf
  fi
  
  # Clean up temporary files
  rm -f /tmp/pf-executable /tmp/pf_parser.py
  
  echo "[pf-install] pf executable installed to /usr/local/bin/pf"
  
  # Check if required Python packages are available
  echo "[pf-install] Checking Python dependencies..."
  if ! python3 -c "import fabric" >/dev/null 2>&1; then
    echo "[pf-install] Warning: Python 'fabric' package not found."
    echo "[pf-install] Install with: pip3 install 'fabric>=3.2,<4'"
  fi
  
  if ! python3 -c "import lark" >/dev/null 2>&1; then
    echo "[pf-install] Warning: Python 'lark' package not found."
    echo "[pf-install] Install with: pip3 install lark"
  fi
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE_NAME="$2"; shift 2;;
    --runtime)
      RUNTIME="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

choose_runtime
build_base_image
build_image
install_executable

echo "[pf-install] Installation complete!"
echo "[pf-install] The 'pf' command is now available in /usr/local/bin"
echo "[pf-install] Run 'pf list' to verify the installation."
echo ""
echo "[pf-install] Note: Make sure you have the required Python dependencies:"
echo "[pf-install]   pip3 install 'fabric>=3.2,<4' lark"

exit 0
