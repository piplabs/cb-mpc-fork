#!/bin/bash
#
# Build the cb-mpc TDH2 WASM module for use by the TypeScript SDK.
#
# Prerequisites:
#   1. Emscripten SDK activated (source emsdk_env.sh)
#   2. OpenSSL built for WASM: make openssl-wasm
#   3. libcbmpc.a built for WASM: make build-wasm
#
# Output:
#   wasm/dist/cb-mpc-tdh2.js    — ES module loader
#   wasm/dist/cb-mpc-tdh2.wasm  — WASM binary
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify prerequisites
if ! command -v em++ &> /dev/null; then
  echo "ERROR: em++ not found. Please activate Emscripten SDK first."
  exit 1
fi

LIB_DIR="${PROJECT_ROOT}/lib/Release"
OPENSSL_DIR="${CBMPC_OPENSSL_ROOT:-${PROJECT_ROOT}/vendors/openssl-wasm}"
OUT_DIR="${SCRIPT_DIR}/dist"

if [ ! -f "${LIB_DIR}/libcbmpc.a" ]; then
  echo "ERROR: libcbmpc.a not found at ${LIB_DIR}"
  echo "Run: make build-wasm"
  exit 1
fi

if [ ! -f "${OPENSSL_DIR}/lib/libcrypto.a" ]; then
  echo "ERROR: WASM OpenSSL not found at ${OPENSSL_DIR}"
  echo "Run: make openssl-wasm"
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "Building cb-mpc TDH2 WASM module..."

em++ -O0 -g \
  -std=c++17 \
  -fno-operator-names \
  -DNO_DEPRECATED_OPENSSL \
  -DOPENSSL_NO_SECURE_MEMORY \
  -DNO_STACK_TRACE \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s EXPORT_NAME="createCbMpcModule" \
  -s EXPORTED_FUNCTIONS='[
    "_malloc",
    "_free",
    "_wasm_tdh2_pub_key_from_point",
    "_wasm_tdh2_free_pub_key",
    "_wasm_tdh2_encrypt",
    "_wasm_tdh2_verify",
    "_wasm_ac_new_node",
    "_wasm_ac_add_child",
    "_wasm_ac_set_node_pid",
    "_wasm_ac_new",
    "_wasm_ac_free",
    "_wasm_tdh2_combine",
    "_wasm_ptr_size",
    "_wasm_seed_random",
    "_wasm_test_uint128"
  ]' \
  -s EXPORTED_RUNTIME_METHODS='["getValue","setValue","HEAPU8","HEAP32"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s ENVIRONMENT='web,node' \
  -s NO_EXIT_RUNTIME=1 \
  -s FILESYSTEM=1 \
  -s ASSERTIONS=0 \
  -I "${PROJECT_ROOT}/src/" \
  -I "${OPENSSL_DIR}/include" \
  "${SCRIPT_DIR}/tdh2_wasm.cpp" \
  -L "${LIB_DIR}" -lcbmpc \
  -L "${OPENSSL_DIR}/lib" -lcrypto \
  -o "${OUT_DIR}/cb-mpc-tdh2.js"

echo ""
echo "Build complete!"
echo "  ${OUT_DIR}/cb-mpc-tdh2.js"
echo "  ${OUT_DIR}/cb-mpc-tdh2.wasm"
ls -lh "${OUT_DIR}/cb-mpc-tdh2.js" "${OUT_DIR}/cb-mpc-tdh2.wasm"
