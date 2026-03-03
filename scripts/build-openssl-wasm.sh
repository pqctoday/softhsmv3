#!/usr/bin/env bash
# build-openssl-wasm.sh — Build OpenSSL 3.6.0 as a static WASM library.
#
# Output: deps/openssl-wasm/lib/libcrypto.a  (+ headers in deps/openssl-wasm/include/)
# Idempotent: skips the build if the output already exists.
#
# Requirements: emcc 3.x+ in PATH.

set -euo pipefail

OSSL_VERSION=3.6.0
OSSL_SHA256="b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="$ROOT/deps/openssl-wasm"
SRC_DIR="$ROOT/deps/openssl-src"

if [[ -f "$INSTALL_DIR/lib/libcrypto.a" ]]; then
    echo "[build-openssl-wasm] Already built. Remove $INSTALL_DIR to rebuild."
    exit 0
fi

# Check emcc
if ! command -v emcc &>/dev/null; then
    echo "[build-openssl-wasm] ERROR: emcc not found in PATH" >&2
    exit 1
fi
echo "[build-openssl-wasm] Using $(emcc --version 2>&1 | head -1)"

mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

TARBALL="openssl-${OSSL_VERSION}.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
    echo "[build-openssl-wasm] Downloading OpenSSL ${OSSL_VERSION}..."
    curl -fL "https://www.openssl.org/source/${TARBALL}" -o "$TARBALL"
fi

# Verify checksum (portable: shasum -a 256 works on both Linux and macOS)
echo "[build-openssl-wasm] Verifying SHA-256..."
ACTUAL_SHA256=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
if [[ "$ACTUAL_SHA256" != "$OSSL_SHA256" ]]; then
    echo "[build-openssl-wasm] ERROR: SHA-256 mismatch for ${TARBALL}" >&2
    echo "[build-openssl-wasm]   expected: ${OSSL_SHA256}" >&2
    echo "[build-openssl-wasm]   actual:   ${ACTUAL_SHA256}" >&2
    rm -f "$TARBALL"
    exit 1
fi
echo "[build-openssl-wasm] Checksum OK."

OSSL_SRC="$SRC_DIR/openssl-${OSSL_VERSION}"
if [[ ! -d "$OSSL_SRC" ]]; then
    echo "[build-openssl-wasm] Extracting..."
    tar xzf "$TARBALL" -C "$SRC_DIR"
fi

cd "$OSSL_SRC"

echo "[build-openssl-wasm] Configuring OpenSSL ${OSSL_VERSION} for Emscripten (linux-generic32 + emcc)..."
# OpenSSL 3.6.0 does not have a built-in wasm32-unknown-emscripten target.
# Use linux-generic32 with emcc/emar/emranlib as the cross-compiler toolchain.
# Do NOT use 'emcmake' — that is for CMake projects, not OpenSSL's Perl Configure.
env CC=emcc AR=emar RANLIB=emranlib perl "$OSSL_SRC/Configure" linux-generic32 \
    --prefix="$INSTALL_DIR" \
    no-shared \
    no-asm \
    no-engine \
    no-threads \
    no-ssl \
    no-tls \
    no-dtls \
    no-sock \
    no-tests \
    no-apps \
    no-docs \
    no-module \
    -DOPENSSL_NO_SECURE_MEMORY

NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[build-openssl-wasm] Building with ${NCPU} jobs..."
make -j"$NCPU" build_libs

echo "[build-openssl-wasm] Installing headers and libraries..."
make install_dev

echo "[build-openssl-wasm] Done."
echo "[build-openssl-wasm] Output: $INSTALL_DIR/lib/libcrypto.a"
ls -lh "$INSTALL_DIR/lib/libcrypto.a"
