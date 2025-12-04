#!/usr/bin/env bash
# Container-based installer for pf (alternative method)
# Builds the pf-runner image for users who prefer containerized execution.
#
# For direct host installation, use ./install.sh instead.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="pf-runner:local"
BASE_IMAGE="localhost/pf-base:latest"
RUNTIME=""

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[pf-container]${NC} $*"; }
log_success() { echo -e "${GREEN}[pf-container]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[pf-container]${NC} $*"; }
log_error() { echo -e "${RED}[pf-container]${NC} $*"; }

usage() {
  cat <<'USAGE'
Usage: ./install-container.sh [--image NAME] [--runtime docker|podman]

Builds the pf-runner container images for containerized workflows.

This is useful for:
  - Running pf tasks that require container-specific dependencies
  - Isolation from host system
  - Reproducible environments

For direct host installation, use: ./install.sh

Options:
  --image NAME       Image tag to build (default: pf-runner:local)
  --runtime NAME     Container runtime to use (auto-detects docker then podman)
  -h, --help         Show this help
USAGE
}

choose_runtime() {
  if [[ -n "${RUNTIME}" ]]; then
    if ! command -v "${RUNTIME}" >/dev/null 2>&1; then
      log_error "Specified runtime '${RUNTIME}' not found"
      exit 1
    fi
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
  else
    log_error "No container runtime found (install docker or podman)"
    exit 1
  fi
}

build_base_image() {
  log_info "Building base image '${BASE_IMAGE}' with ${RUNTIME}..."
  ${RUNTIME} build -f "${ROOT_DIR}/containers/dockerfiles/Dockerfile.base" -t "${BASE_IMAGE}" "${ROOT_DIR}"
  log_success "Base image built: ${BASE_IMAGE}"
}

build_image() {
  log_info "Building image '${IMAGE_NAME}' with ${RUNTIME}..."
  ${RUNTIME} build -f "${ROOT_DIR}/containers/dockerfiles/Dockerfile.pf-runner" -t "${IMAGE_NAME}" "${ROOT_DIR}"
  log_success "Image built: ${IMAGE_NAME}"
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

log_info "pf container image builder"
log_info "==========================="

choose_runtime
build_base_image
build_image

log_success "Container images built successfully!"
log_info ""
log_info "To run pf from container:"
log_info "  ${RUNTIME} run --rm -it -v \"\$(pwd):/work\" -w /work ${IMAGE_NAME} pf list"
log_info ""
log_info "For host installation, use: ./install.sh"

exit 0
