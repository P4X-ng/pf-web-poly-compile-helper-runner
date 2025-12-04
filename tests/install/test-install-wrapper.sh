#!/usr/bin/env bash
# Smoke test for pf-web-poly-compile-helper-runner install script
# - Verifies containers/dockerfiles still build a pf-runner image
# - Uses a test image tag and skips writing the wrapper by default

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

main() {
  cd "${PROJECT_ROOT}"

  if ! command -v podman >/dev/null 2>&1; then
    log_warn "podman not found; skipping install smoke test (containers not available)"
    exit 0
  fi

  # Use a test image tag so we don't interfere with user's main image
  local test_image="pf-runner:test-install"

  log_info "Running ./install.sh smoke test with podman (image=${test_image})"

  # Build images but skip wrapper so we don't touch ~/.local/bin/pf
  PF_IMAGE="${test_image}" ./install.sh --runtime podman --image "${test_image}" --no-wrapper >/dev/null

  # Verify image exists
  if podman image exists "${test_image}" >/dev/null 2>&1; then
    log_pass "Install script successfully built image ${test_image} with podman"
    exit 0
  else
    log_fail "Install script did not produce image ${test_image}"
    exit 1
  fi
}

main "$@"
