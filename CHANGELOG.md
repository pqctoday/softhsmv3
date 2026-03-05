# Changelog

All notable changes to SoftHSMv3 are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `CKM_SP800_108_FEEDBACK_KDF` (`0x000003ad`) — NIST SP 800-108 §4.2 feedback mode KBKDF;
  `CK_SP800_108_FEEDBACK_KDF_PARAMS` parser with optional IV/seed (`OSSL_KDF_PARAM_SEED`);
  OpenSSL KBKDF `MODE=FEEDBACK`; registered in `SoftHSM_slots.cpp` (G-PK2)
- `CKM_ECDH1_COFACTOR_DERIVE` (`0x00001051`) — cofactor ECDH key agreement per NIST SP 800-56A
  §5.7.1.2; `OSSLECDH::deriveKeyWithCofactor()` inserts `EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1)`;
  eliminates small-subgroup attacks on non-prime-order curves; registered in `SoftHSM_slots.cpp` (G-PK4)

### Fixed
- **`C_DeriveKey` validation switch** (`SoftHSM_keygen.cpp`): Added missing `case` labels for
  `CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`, and
  `CKM_ECDH1_COFACTOR_DERIVE` in the pre-dispatch `switch(pMechanism->mechanism)` block;
  without these labels the handlers added for G-5G3, G-PK1, G-PK2, and G-PK4 were
  unreachable — `C_DeriveKey` returned `CKR_MECHANISM_INVALID` for all four mechanisms

---

### Added (community / project)
- `CONTRIBUTING.md` — PR process, code style, sanitizer build instructions
- `SECURITY.md` — vulnerability disclosure channel and security design notes
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `CHANGELOG.md` — this file
- `softhsmv3.pc.in` — pkg-config template; `cmake --install` now installs
  `<libdir>/pkgconfig/softhsmv3.pc` so consumers can use `pkg-config --cflags --libs softhsmv3`
- Header install target: `cmake --install` now copies `pkcs11.h`, `pkcs11f.h`,
  `pkcs11t.h`, `cryptoki.h` to `<includedir>/softhsm/`
- `cmake/modules/CompilerSanitizers.cmake` — `-DENABLE_ASAN=ON`,
  `-DENABLE_UBSAN=ON`, `-DENABLE_TSAN=ON` options for debug/CI builds
- `Doxyfile.in` + CMake `docs` target: run `cmake --build build --target docs`
  to generate HTML API reference in `build/docs/html/`; all public methods in
  `SecureDataManager.h` carry `/** ... */` Doxygen docstrings (M5)
- Coverage job in `.github/workflows/ci.yml`: gcov-instrumented build, lcov
  capture with system/test path filtering, upload to Codecov via
  `codecov/codecov-action@v4` (M6)

### Changed

- `src/lib/SoftHSM.cpp` — `MacSignInit` / `MacVerifyInit`: replaced 11-case
  duplicate switch blocks with a shared `kMacMechTable[]` lookup array and
  `resolveMacMech()` helper; reduces duplication and makes adding new HMAC/CMAC
  mechanisms a one-line table entry (H3)
- `src/lib/SoftHSM.cpp` — replaced six raw magic numbers with named constants
  in anonymous namespace: `UNLIMITED_KEY_SIZE` (0x80000000), `MAX_GENERIC_KEY_LEN_BYTES`
  (0x8000000), `MAX_HMAC_KEY_BYTES` (512), `AES_KEY_BYTES_128/192/256`
  (16/24/32); zero compiler warnings after change (Md1)
- `src/lib/SoftHSM.h` — replaced 12 concrete key-type `#include` headers with
  forward declarations; reduces cascading recompilation when OSSL key headers
  change (Md2)
- `src/lib/SoftHSM.cpp` (11,786 ln) split into 8 domain-focused translation
  units; all 132 `SoftHSM::` member functions preserved exactly once across
  the new files (H1):
  - `SoftHSM_slots.cpp` (~948 ln) — `C_Initialize` … `C_SetPIN`
  - `SoftHSM_sessions.cpp` (~232 ln) — `C_OpenSession` … `C_Logout`
  - `SoftHSM_objects.cpp` (~973 ln) — `C_CreateObject` … `C_FindObjectsFinal` + `CreateObject`
  - `SoftHSM_cipher.cpp` (~1296 ln) — `SymEncryptInit` … `C_DecryptFinal`
  - `SoftHSM_digest.cpp` (~330 ln) — `C_DigestInit` … `C_DigestFinal`
  - `SoftHSM_sign.cpp` (~2297 ln) — `MacSignInit` … `C_DecryptVerifyUpdate`
  - `SoftHSM_keygen.cpp` (~5237 ln) — `C_GenerateKey` … `MechParamCheckRSAAESKEYWRAP`
  - `SoftHSM_kem.cpp` (~482 ln) — `C_EncapsulateKey`, `C_DecapsulateKey`
  - `SoftHSM.cpp` residual (~421 ln) — shared helpers, singleton, RNG, `isMechanismPermitted`
- `src/lib/SoftHSMHelpers.h` (new) — private header shared across split TUs:
  named constants (`UNLIMITED_KEY_SIZE`, `MAX_HMAC_KEY_BYTES`, `AES_KEY_BYTES_*`)
  and cross-TU free-function declarations (`resetMutexFactoryCallbacks`,
  `checkKeyLength`, `extractObjectInformation`)
- `src/lib/SoftHSM.cpp` — extracted `acquireSession` / `acquireSessionToken` /
  `acquireSessionTokenKey` private helpers eliminating the 5-step
  session/token/key acquisition block repeated ~76× across `C_*Init` functions
  (H2); net −257 lines (180 added, 437 deleted)
- `src/lib/SoftHSM.cpp` — extracted `cleanupKeyPair` private helper
  eliminating the identical 20-line error-recovery block from all 6 key
  generators (`generateRSA/EC/ED/MLDSA/SLHDSA/MLKEM`) (H5)

### Fixed
- **P0 — Integer underflow in `UnwrapMechRsaAesKw`** (`SoftHSM.cpp`): Added
  bounds check before unsigned subtraction `wrappedLen2 = ulWrappedKeyLen -
  wrappedLen1`; returns `CKR_WRAPPED_KEY_LEN_RANGE` on underflow
- **P0 — Integer overflow in `SymEncryptUpdate`** (`SoftHSM.cpp`): Added
  overflow guard on `ulDataLen + remainingSize` before buffer allocation;
  returns `CKR_DATA_LEN_RANGE` on overflow
- **P1 — Session stuck in `SESSION_OP_FIND`** (`SoftHSM.cpp`): Three error
  paths in `C_FindObjectsInit` now call `session->resetOp()` before returning
  so that callers can retry the operation
- **P1 — `SecureDataManager` AES cipher race** (`SecureDataManager.cpp`):
  Removed shared `SymmetricAlgorithm* aes` member; each function now creates
  a per-call local AES instance eliminating use-without-lock races in
  multi-threaded token access
- **P2 — Unbounded heap allocation in `File::readByteString`** (`File.cpp`):
  Added 64 MiB sanity cap on length field read from untrusted on-disk object
  store; returns `false` with `ERROR_MSG` instead of calling `resize(len)` on
  a gigabyte-scale attacker-controlled value
- **P2 — `assert()` in production code** (`SlotManager.cpp`): Replaced two
  `assert()` calls (no-op in release builds) with defensive `ERROR_MSG` +
  `return CKR_GENERAL_ERROR` / slot discard; removed `<cassert>` include

---

## [3.0.0] — 2025-Q4

### Added
- **Phase 0**: Import SoftHSM2 v2.7.0 baseline; replace legacy autotools with
  CMake; drop ENGINE API; OpenSSL 3.x EVP-only backend
- **Phase 1**: Full OpenSSL 3.x EVP API migration; require OpenSSL ≥ 3.3;
  CI deprecated-API scan
- **Phase 2**: ML-DSA (FIPS 204 / PKCS#11 v3.2) sign/verify via OpenSSL EVP;
  `C_SignMessage` / `C_VerifyMessage` multi-part variants
- **Phase 3**: ML-KEM (FIPS 203 / PKCS#11 v3.2) `C_EncapsulateKey` /
  `C_DecapsulateKey`; SLH-DSA support
- **Phase 4**: Emscripten WASM target (`softhsm.js` + `softhsm.wasm`);
  Modularize=1 factory; PKCS11 v3.2 export list (71 C_* functions + malloc/free)
- **Phase 5**: npm package `@pqctoday/softhsm-wasm` with TypeScript declarations

[Unreleased]: https://github.com/pqctoday/softhsmv3/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/pqctoday/softhsmv3/releases/tag/v3.0.0
