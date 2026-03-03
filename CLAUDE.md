# CLAUDE.md — softhsmv3

PQC-enabled fork of SoftHSM2 v2.7.0. OpenSSL-only backend, PKCS#11 v3.2,
ML-DSA (FIPS 204) + ML-KEM (FIPS 203), targeting Emscripten WASM for
in-browser HSM emulation in the PQC Timeline App.

## Build

```bash
# Native build (macOS/Linux)
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build -j$(nproc)

# Run tests
cd build && make check

# Emscripten WASM build (Phase 4)
emcmake cmake -B build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm
```

Requirements: OpenSSL >= 3.5, CMake >= 3.16, C++17 compiler.

## Architecture

**Single backend: OpenSSL EVP-only.** No Botan, no ENGINE-based APIs.

```
src/lib/
  crypto/           # Crypto implementations (OSSL* + abstract bases)
  pkcs11/           # PKCS#11 v3.2 headers (pkcs11.h, pkcs11f.h, pkcs11t.h)
  SoftHSM.cpp/h     # Main PKCS#11 dispatch + mechanism table
  common/           # Utilities (logging, config, byte strings)
  data_mgr/         # Secure data management
  object_store/     # Token + session object store
  session_mgr/      # Session lifecycle
  slot_mgr/         # Slot and token management
  handle_mgr/       # Handle allocation
src/bin/
  softhsm2-util/    # CLI tool
  softhsm2-keyconv/ # Key conversion utility
```

**Retained algorithms**: RSA, ECDSA, ECDH, EdDSA, AES, SHA-1/224/256/384/512, HMAC, CMAC.

**PQC additions (Phase 2+)**: ML-DSA-44/65/87, ML-KEM-512/768/1024.

## Coding Conventions

- **C++17 only** — use structured bindings, `std::optional`, `[[nodiscard]]` where appropriate
- **EVP-only OpenSSL API** — never use deprecated `RSA_*`, `EC_KEY_*`, `ENGINE_*` functions
- Use `EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)` pattern for all key operations
- New PQC algorithms follow the EdDSA file pattern: `OSSLMLxxx.cpp/h`, `OSSLMLxxxKeyPair.cpp/h`, `OSSLMLxxxPublicKey.cpp/h`, `OSSLMLxxxPrivateKey.cpp/h`
- All error paths must call `CryptoFactory::logError()` or use the existing `ERROR_MSG()` macro
- PKCS#11 function implementations live in `src/lib/SoftHSM.cpp`
- New mechanisms registered in `SoftHSM::prepareSupportedMechanisms()`
- New key types registered in `OSSLCryptoFactory::getAsymmetricAlgorithm()`

## Phase Roadmap

| Phase | Issue | Status | Description |
|-------|-------|--------|-------------|
| 0 | #1 | In Progress | Import SoftHSMv2 v2.7.0 + PKCS#11 v3.2 + strip legacy |
| 1 | #2 | Pending | OpenSSL 3.x EVP API migration |
| 2 | #3 | Pending | ML-DSA (FIPS 204, PKCS#11 v3.2) |
| 3 | #4 | Pending | ML-KEM + C_EncapsulateKey / C_DecapsulateKey |
| 4 | #5 | Pending | Emscripten WASM build |
| 5 | #6 | Pending | npm package (@pqctoday/softhsm-wasm) |
| 6 | #7 | Pending | PQC Timeline App integration |

## Key PKCS#11 v3.2 Constants (PQC)

```c
CKK_ML_KEM              = 0x00000049
CKK_ML_DSA              = 0x0000004a
CKM_ML_KEM              = 0x00000017
CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001c
CKM_ML_DSA              = 0x0000001d
CKA_PARAMETER_SET       = 0x00000601  // CKP_ML_DSA_44/65/87, CKP_ML_KEM_512/768/1024
CKA_ENCAPSULATE         = 0x00000623
CKA_DECAPSULATE         = 0x00000624
CKA_SEED                = 0x00000602  // 32-byte deterministic seed for ML-DSA keygen
```

New functions in pkcs11f.h:
- `C_EncapsulateKey` — ML-KEM encapsulation
- `C_DecapsulateKey` — ML-KEM decapsulation

## References

- [SoftHSM2 upstream](https://github.com/softhsm/SoftHSMv2)
- [PKCS#11 v3.2 CSD01](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.html)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [OpenSSL EVP_PKEY-ML-DSA](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)
- [OpenSSL EVP_PKEY-ML-KEM](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
