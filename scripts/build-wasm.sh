#!/usr/bin/env bash
# build-wasm.sh — End-to-end Emscripten WASM build for SoftHSMv3.
#
# Prerequisites:
#   - emcc 3.x+ in PATH
#   - cmake 3.16+
#
# Output:
#   wasm/softhsm.js   — Emscripten JS wrapper (MODULARIZE=1, createSoftHSMModule)
#   wasm/softhsm.wasm — WASM binary
#
# Usage:
#   bash scripts/build-wasm.sh            # full build
#   SKIP_OPENSSL=1 bash scripts/build-wasm.sh  # skip OpenSSL WASM rebuild

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS_OPENSSL="$ROOT/deps/openssl-wasm"
BUILD_DIR="$ROOT/build-wasm"
OUTPUT_DIR="$ROOT/wasm"

# Check emcc
if ! command -v emcc &>/dev/null; then
    echo "[build-wasm] ERROR: emcc not found in PATH" >&2
    echo "[build-wasm] Install Emscripten: https://emscripten.org/docs/getting_started/" >&2
    exit 1
fi
echo "[build-wasm] emcc: $(emcc --version 2>&1 | head -1)"

# --- Step 1: Build OpenSSL WASM if needed ---
if [[ "${SKIP_OPENSSL:-0}" == "1" ]]; then
    echo "[build-wasm] Skipping OpenSSL WASM build (SKIP_OPENSSL=1)"
else
    bash "$ROOT/scripts/build-openssl-wasm.sh"
fi

if [[ ! -f "$DEPS_OPENSSL/lib/libcrypto.a" ]]; then
    echo "[build-wasm] ERROR: $DEPS_OPENSSL/lib/libcrypto.a not found" >&2
    echo "[build-wasm] Run: bash scripts/build-openssl-wasm.sh" >&2
    exit 1
fi

# --- Step 2: CMake configure ---
echo "[build-wasm] Configuring (build dir: $BUILD_DIR)..."
mkdir -p "$BUILD_DIR"

emcmake cmake "$ROOT" \
    -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/toolchain/emscripten.cmake" \
    -DOPENSSL_ROOT_DIR="$DEPS_OPENSSL" \
    -DOPENSSL_INCLUDE_DIR="$DEPS_OPENSSL/include" \
    -DOPENSSL_CRYPTO_LIBRARY="$DEPS_OPENSSL/lib/libcrypto.a" \
    -DOPENSSL_SSL_LIBRARY="$DEPS_OPENSSL/lib/libssl.a" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_OBJECTSTORE_BACKEND_DB=OFF \
    -DDISABLE_NON_PAGED_MEMORY=ON \
    -DBUILD_TESTS=OFF \
    -DENABLE_STATIC=OFF

# --- Step 3: Build ---
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[build-wasm] Building with ${NCPU} jobs..."
emmake cmake --build "$BUILD_DIR" --target softhsmv3 -j"$NCPU"

# --- Step 4: Copy outputs ---
mkdir -p "$OUTPUT_DIR"

JS_FILE="$BUILD_DIR/src/lib/libsofthsmv3.js"
WASM_FILE="$BUILD_DIR/src/lib/libsofthsmv3.wasm"

if [[ ! -f "$JS_FILE" ]]; then
    echo "[build-wasm] ERROR: Expected output not found: $JS_FILE" >&2
    echo "[build-wasm] Check build logs above for errors." >&2
    exit 1
fi

# Patch the WASM filename reference inside the JS wrapper (emcc uses the lib-prefixed name)
sed 's/libsofthsmv3\.wasm/softhsm.wasm/g' "$JS_FILE" > "$OUTPUT_DIR/softhsm.js"
cp "$WASM_FILE" "$OUTPUT_DIR/softhsm.wasm"

echo ""
echo "[build-wasm] Build complete."
echo "[build-wasm] Output:"
ls -lh "$OUTPUT_DIR/softhsm.js" "$OUTPUT_DIR/softhsm.wasm"
echo ""
echo "[build-wasm] Smoke test:"
echo "  node tests/smoke-wasm.mjs"
