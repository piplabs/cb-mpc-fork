#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_TYPE="${BUILD_TYPE:-Release}"

DO_CD=1
if [[ $# -gt 0 && "$1" == "--no-cd" ]]; then
  DO_CD=0
  shift
fi

# Auto-detect OpenSSL location if not set
if [[ -z "${CBMPC_OPENSSL_ROOT:-}" ]]; then
  if command -v brew >/dev/null 2>&1; then
    DETECTED_OPENSSL="$(brew --prefix openssl@3 2>/dev/null || true)"
    if [[ -n "${DETECTED_OPENSSL}" && -d "${DETECTED_OPENSSL}" ]]; then
      export CBMPC_OPENSSL_ROOT="${DETECTED_OPENSSL}"
      echo "[go_with_cpp] Auto-detected OpenSSL: ${CBMPC_OPENSSL_ROOT}"
    fi
  fi
fi

INC_DIR="${REPO_ROOT}/src"
LIB_DIRS=(
  "${REPO_ROOT}/build/${BUILD_TYPE}/lib"
  "${REPO_ROOT}/lib/${BUILD_TYPE}"
)

LDFLAGS_ACCUM=()
for d in "${LIB_DIRS[@]}"; do
  LDFLAGS_ACCUM+=("-L${d}")
done

# Add OpenSSL include path to CGO flags if available
CFLAGS_ACCUM="-I${INC_DIR}"
if [[ -n "${CBMPC_OPENSSL_ROOT:-}" ]]; then
  CFLAGS_ACCUM="${CFLAGS_ACCUM} -I${CBMPC_OPENSSL_ROOT}/include"
  LDFLAGS_ACCUM+=("-L${CBMPC_OPENSSL_ROOT}/lib")
fi

export CGO_CFLAGS="${CFLAGS_ACCUM}"
export CGO_CXXFLAGS="${CFLAGS_ACCUM}"
export CGO_LDFLAGS="${LDFLAGS_ACCUM[*]}"
export BUILD_TYPE

bash "${SCRIPT_DIR}/auto_build_cpp.sh"

if [[ ${DO_CD} -eq 1 ]]; then
  cd "${REPO_ROOT}/demos-go/cb-mpc-go"
fi

bash "${SCRIPT_DIR}/auto_build_cpp.sh"
exec "$@"


