#!/bin/bash

set -e

# Ensure Emscripten is available
if ! command -v emcc &> /dev/null; then
  echo "ERROR: emcc not found. Please install and activate Emscripten SDK first:"
  echo "  git clone https://github.com/emscripten-core/emsdk.git"
  echo "  cd emsdk && ./emsdk install latest && ./emsdk activate latest"
  echo "  source ./emsdk_env.sh"
  exit 1
fi

# Default to a project-local directory to avoid sudo and conflicts with system OpenSSL
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_DIR="${CBMPC_OPENSSL_ROOT:-${PROJECT_ROOT}/vendors/openssl-wasm}"

cd /tmp
curl -L https://github.com/openssl/openssl/releases/download/openssl-3.2.0/openssl-3.2.0.tar.gz --output openssl-3.2.0.tar.gz
expectedHash='14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e'

# Use sha256sum on Linux, shasum on macOS
if command -v sha256sum &> /dev/null; then
  fileHash=$(sha256sum openssl-3.2.0.tar.gz | cut -d " " -f 1)
else
  fileHash=$(shasum -a 256 openssl-3.2.0.tar.gz | cut -d " " -f 1)
fi

if [ "$expectedHash" != "$fileHash" ]
then
  echo 'ERROR: SHA256 DOES NOT MATCH!'
  echo 'expected: ' $expectedHash
  echo 'file:     ' $fileHash
  exit 1
fi

echo "WASM Start"

tar -xzf openssl-3.2.0.tar.gz
cd openssl-3.2.0

# sed -i behaves differently on macOS (BSD) vs Linux (GNU)
if [ "$(uname)" = "Darwin" ]; then
  sed -i '' 's/^static//' crypto/ec/curve25519.c
else
  sed -i 's/^static//' crypto/ec/curve25519.c
fi

# Configure OpenSSL for WASM/Emscripten
# Set compilers directly via env vars — do NOT use emconfigure/emmake wrappers,
# as they mangle the CC path (emcc -> ememcc) when combined with explicit CC= args.
export CC=emcc
export CXX=em++
export AR=emar
export RANLIB=emranlib

./Configure linux-generic32 \
  -static \
  -no-asm \
  -no-threads \
  -no-shared \
  -no-afalgeng -no-apps -no-aria -no-autoload-config -no-bf -no-camellia -no-cast -no-chacha -no-cmac -no-cms -no-crypto-mdebug \
  -no-comp -no-cmp -no-ct -no-des -no-dh -no-dgram -no-dsa -no-dso -no-dtls -no-dynamic-engine -no-ec2m -no-egd -no-engine -no-external-tests \
  -no-gost -no-http -no-idea -no-mdc2 -no-md2 -no-md4 -no-module -no-nextprotoneg -no-ocb -no-ocsp -no-psk -no-padlockeng -no-poly1305 \
  -no-quic -no-rc2 -no-rc4 -no-rc5 -no-rfc3779 -no-scrypt -no-sctp -no-seed -no-siphash -no-sm2 -no-sm3 -no-sm4 -no-sock -no-srtp -no-srp \
  -no-ssl-trace -no-ssl3 -no-stdio -no-tests -no-tls -no-ts -no-unit-test -no-uplink -no-whirlpool -no-zlib \
  -no-hw -no-devcryptoeng \
  -DOPENSSL_NO_SECURE_MEMORY \
  --prefix="${INSTALL_DIR}" --libdir=lib

# Build and install
make build_generated -j4
make libcrypto.a -j4
make install_sw -j4

echo "WASM FINISHED"
echo "OpenSSL for WASM installed to: ${INSTALL_DIR}"
