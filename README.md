# SoftHSMv3 / `@pqctoday/softhsm-wasm`

A modernized fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) with **OpenSSL 3.x**, **PKCS#11 v3.2**, and **post-quantum cryptography** support — compiled to WebAssembly for use in browsers and Node.js.

SoftHSMv3 ships two WASM engines with identical PKCS#11 APIs: a **C++/Emscripten** engine (OpenSSL 3.6 backend) and a **pure-Rust** engine (RustCrypto backend, ~1.3 MB). Both produce the same `_C_*` function exports and are drop-in interchangeable.

## Installation

```bash
npm install @pqctoday/softhsm-wasm
```

## Quick Start

```js
// CJS
const createSoftHSMModule = require('@pqctoday/softhsm-wasm')
const { CK } = require('@pqctoday/softhsm-wasm')

// ESM dynamic import
const { default: createSoftHSMModule, CK } = await import('@pqctoday/softhsm-wasm')

// Named import
const { createSoftHSMModule, CK } = require('@pqctoday/softhsm-wasm')

// ── ML-KEM-768 key encapsulation example ──────────────────────────────────
const M = await createSoftHSMModule()

// Allocate helper
const writeStr = (s) => {
  const len = M.lengthBytesUTF8(s) + 1
  const ptr = M._malloc(len)
  M.stringToUTF8(s, ptr, len)
  return ptr
}

// Initialize + open token
M._C_Initialize(0)
const slotPtr = M._malloc(4)
const slotCountPtr = M._malloc(4)
M._C_GetSlotList(0, slotPtr, slotCountPtr)
const slot = M.getValue(slotPtr, 'i32')

const labelPtr = M._malloc(32)
M.HEAPU8.fill(0x20, labelPtr, labelPtr + 32)   // blank-pad label
M.stringToUTF8('MyToken', labelPtr, 8)
const soPinPtr = writeStr('12345678')
M._C_InitToken(slot, soPinPtr, 8, labelPtr)
M._free(soPinPtr); M._free(labelPtr); M._free(slotPtr); M._free(slotCountPtr)

// Open session, generate ML-KEM-768 key pair, encapsulate, decapsulate
// See tests/smoke-wasm.mjs for the complete lifecycle example.
```

**TypeScript** types are included — import from `'@pqctoday/softhsm-wasm'` for full
`SoftHSMModule` intellisense. Constants are available separately:

```ts
import CK from '@pqctoday/softhsm-wasm/constants'
// CK.CKM_ML_KEM, CK.CKP_ML_KEM_768, CK.CKR_OK, CK.CK_ATTRIBUTE_SIZE, …
```

---

## What's New vs SoftHSM2

| Feature | SoftHSM2 (v2.7.0) | SoftHSMv3 |
| --- | --- | --- |
| OpenSSL backend | 1.x (deprecated APIs) | 3.6 (EVP-only) |
| PKCS#11 version | 3.0 | **3.2** (CSD01, April 2025) |
| ML-KEM (FIPS 203) | Not supported | **ML-KEM-512/768/1024** |
| ML-DSA (FIPS 204) | PR only (#809) | **ML-DSA-44/65/87** |
| SLH-DSA (FIPS 205) | Not supported | **SLH-DSA-SHA2/SHAKE variants** |
| C_EncapsulateKey | Not supported | **Implemented** |
| C_DecapsulateKey | Not supported | **Implemented** |
| C_SignMessage / C_VerifyMessage | Not supported | **Implemented** (v3.0 one-shot + streaming) |
| Message Encrypt/Decrypt API | Not supported | **Implemented** (AES-GCM per-message AEAD) |
| C_VerifySignatureInit / C_VerifySignature | Not supported | **Implemented** (v3.2 pre-bound verify) |
| C_WrapKeyAuthenticated / C_UnwrapKeyAuthenticated | Not supported | **Implemented** (v3.2 AES-GCM key wrap) |
| Key derivation (HKDF, KBKDF, cofactor ECDH) | Not supported | **`CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`, `CKM_ECDH1_COFACTOR_DERIVE`** |
| PBKDF2 (`CKM_PKCS5_PBKD2`) | Not supported | **Implemented** — HMAC-SHA{1/224/256/384/512} PRF; BIP39 / SLIP-0010 seed derivation |
| ECDH1 with KDF (`CKD_SHA*_KDF`) | Not supported | **Implemented** — X9.63 SHA{1/256/384/512} KDF on `CKM_ECDH1_DERIVE`; 5G SUCI deconcealment (TS 33.501 §6.12.2) |
| SHA-3 signature variants | Not supported | **C++:** `CKM_ECDSA_SHA3_224/256/384/512`, `CKM_RSA_SHA3_224/256/384/512_PKCS/_PKCS_PSS` — **Rust:** `CKM_ECDSA_SHA3_224/256/384/512` |
| GOST/DES/DSA/DH | Included | Removed (focused codebase) |
| WASM build | Not supported | **Emscripten + Rust `wasm32-unknown-unknown`** |
| Rust WASM engine | N/A | **Pure Rust (~336 KB), drop-in parity** |
| npm package | N/A | **@pqctoday/softhsm-wasm** |

## PQC Algorithms

### ML-KEM (Key Encapsulation Mechanism) — FIPS 203

| Variant | Public Key | Private Key | Ciphertext | Shared Secret | NIST Level |
| --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 800 B | 1,632 B | 768 B | 32 B | 1 |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B | 32 B | 3 |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B | 32 B | 5 |

### ML-DSA (Digital Signature Algorithm) — FIPS 204

| Variant | Public Key | Private Key | Signature | NIST Level |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 1,312 B | 2,560 B | 2,420 B | 2 |
| ML-DSA-65 | 1,952 B | 4,032 B | 3,293 B | 3 |
| ML-DSA-87 | 2,592 B | 4,896 B | 4,627 B | 5 |

### SLH-DSA (Stateless Hash-Based Signature) — FIPS 205

| Variant | Public Key | Private Key | Signature | NIST Level |
| --- | --- | --- | --- | --- |
| SLH-DSA-SHA2-128s | 32 B | 64 B | 7,856 B | 1 (small) |
| SLH-DSA-SHA2-128f | 32 B | 64 B | 17,088 B | 1 (fast) |
| SLH-DSA-SHA2-192s | 48 B | 96 B | 16,224 B | 3 (small) |
| SLH-DSA-SHA2-192f | 48 B | 96 B | 35,664 B | 3 (fast) |
| SLH-DSA-SHA2-256s | 64 B | 128 B | 29,792 B | 5 (small) |
| SLH-DSA-SHA2-256f | 64 B | 128 B | 49,856 B | 5 (fast) |
| SLH-DSA-SHAKE-128s/f | 32 B | 64 B | 7,856/17,088 B | 1 |
| SLH-DSA-SHAKE-192s/f | 48 B | 96 B | 16,224/35,664 B | 3 |
| SLH-DSA-SHAKE-256s/f | 64 B | 128 B | 29,792/49,856 B | 5 |

## PKCS#11 v3.2 Mechanisms

### Key Encapsulation

```c
CKM_ML_KEM_KEY_PAIR_GEN  // Key pair generation
CKM_ML_KEM               // Encapsulate / Decapsulate
C_EncapsulateKey()        // KEM encapsulation (v3.2)
C_DecapsulateKey()        // KEM decapsulation (v3.2)
```

### Digital Signatures — ML-DSA

```c
CKM_ML_DSA_KEY_PAIR_GEN  // Key pair generation
CKM_ML_DSA               // Pure ML-DSA sign/verify (one-shot and message-session)
CKM_HASH_ML_DSA_SHA224   // Pre-hash ML-DSA variants
CKM_HASH_ML_DSA_SHA256
CKM_HASH_ML_DSA_SHA384
CKM_HASH_ML_DSA_SHA512
CKM_HASH_ML_DSA_SHA3_224
CKM_HASH_ML_DSA_SHA3_256
CKM_HASH_ML_DSA_SHA3_384
CKM_HASH_ML_DSA_SHA3_512
CKM_HASH_ML_DSA_SHAKE128
CKM_HASH_ML_DSA_SHAKE256
```

### Digital Signatures — SLH-DSA

```c
CKM_SLH_DSA_KEY_PAIR_GEN // Key pair generation
CKM_SLH_DSA              // Pure SLH-DSA sign/verify
CKM_HASH_SLH_DSA_SHA224  // Pre-hash SLH-DSA variants (11 total)
CKM_HASH_SLH_DSA_SHA256
CKM_HASH_SLH_DSA_SHA384
CKM_HASH_SLH_DSA_SHA512
CKM_HASH_SLH_DSA_SHA3_224
CKM_HASH_SLH_DSA_SHA3_256
CKM_HASH_SLH_DSA_SHA3_384
CKM_HASH_SLH_DSA_SHA3_512
CKM_HASH_SLH_DSA_SHAKE128
CKM_HASH_SLH_DSA_SHAKE256
```

### Message Signing API (v3.0)

```c
// One-shot per-message signing within a message session
C_MessageSignInit()       // Open a message-signing session
C_SignMessage()           // Sign one message (one-shot)
C_SignMessageBegin()      // Begin a two-step message sign
C_SignMessageNext()       // Complete the sign (or size-query)
C_MessageSignFinal()      // Close the session

// Symmetric (verify side)
C_MessageVerifyInit()
C_VerifyMessage()
C_VerifyMessageBegin()
C_VerifyMessageNext()
C_MessageVerifyFinal()
```

### Per-Message AEAD (v3.0)

```c
// AES-GCM encrypt/decrypt with per-message IV generation
C_MessageEncryptInit()    // Open an encrypt-message session
C_EncryptMessage()        // Encrypt one message (one-shot)
C_EncryptMessageBegin()   // Begin streaming encrypt
C_EncryptMessageNext()    // Stream plaintext chunk / finalize
C_MessageEncryptFinal()   // Close the session

C_MessageDecryptInit()
C_DecryptMessage()
C_DecryptMessageBegin()
C_DecryptMessageNext()
C_MessageDecryptFinal()
```

### Pre-Bound Signature Verification (v3.2)

```c
// Verify a signature against data received afterwards (signature-first pattern)
C_VerifySignatureInit()   // Bind signature and algorithm to session
C_VerifySignature()       // Verify against data (one-shot)
```

### Authenticated Key Wrap/Unwrap (v3.2)

```c
// AES-GCM authenticated key wrapping (replaces C_WrapKey for PQC key sizes)
C_WrapKeyAuthenticated()
C_UnwrapKeyAuthenticated()
```

### Classical Signatures — SHA-3 variants

```c
// ECDSA with SHA-3 pre-hash (C++ and Rust engines)
CKM_ECDSA_SHA3_224         = 0x00001047
CKM_ECDSA_SHA3_256         = 0x00001048
CKM_ECDSA_SHA3_384         = 0x00001049
CKM_ECDSA_SHA3_512         = 0x0000104a

// RSA PKCS#1 v1.5 with SHA-3 (C++ engine)
CKM_RSA_SHA3_224_PKCS      = 0x0000004f
CKM_RSA_SHA3_256_PKCS      = 0x00000050
CKM_RSA_SHA3_384_PKCS      = 0x00000051
CKM_RSA_SHA3_512_PKCS      = 0x00000052

// RSA-PSS with SHA-3 (C++ engine)
CKM_RSA_SHA3_224_PKCS_PSS  = 0x00000053
CKM_RSA_SHA3_256_PKCS_PSS  = 0x00000054
CKM_RSA_SHA3_384_PKCS_PSS  = 0x00000055
CKM_RSA_SHA3_512_PKCS_PSS  = 0x00000056
```

### Key Derivation

```c
// PBKDF2 (RFC 2898) — password-based key derivation (PKCS#11 v3.2 §5.7.3.1)
// PRFs: CKP_PKCS5_PBKD2_HMAC_{SHA1, SHA224, SHA256, SHA384, SHA512}
// Typical use: BIP39 mnemonic → 64-byte seed, SLIP-0010 child keys
// pPassword in CK_PKCS5_PBKD2_PARAMS2; hBaseKey must be 0
CKM_PKCS5_PBKD2            = 0x000003b0

// ECDH1 with X9.63 KDF variants — SharedInfo passed as OSSL_KDF_PARAM_INFO
// Used for 5G SUCI deconcealment (Profile A: X25519, Profile B: P-256)
CKM_ECDH1_DERIVE           = 0x00001050  // + CKD_SHA{1,256,384,512}_KDF

// HKDF (RFC 5869) — extract + expand (PKCS#11 v3.2 §2.41)
CKM_HKDF_DERIVE            = 0x0000402a

// NIST SP 800-108 Counter mode KBKDF — K(i) = PRF(K, i ∥ Label ∥ Context)
CKM_SP800_108_COUNTER_KDF  = 0x000003ac

// NIST SP 800-108 Feedback mode KBKDF — K(i) = PRF(K, K(i−1) ∥ Label ∥ Context)
CKM_SP800_108_FEEDBACK_KDF = 0x000003ad

// Cofactor ECDH — multiplies shared secret by curve cofactor before KDF
// Eliminates small-subgroup attacks per NIST SP 800-56A §5.7.1.2
CKM_ECDH1_COFACTOR_DERIVE  = 0x00001051
```

## Rust WASM Engine (`rust/`)

The Rust engine is a pure-Rust reimplementation of the SoftHSMv3 PKCS#11 surface, compiled to `wasm32-unknown-unknown` via `wasm-bindgen`. It replaces the entire OpenSSL backend with native RustCrypto crates, producing a standalone ~1.3 MB `.wasm` binary with zero C dependencies.

### Why Two Engines?

| | C++/Emscripten | Rust |
| --- | --- | --- |
| Crypto backend | OpenSSL 3.6 (EVP) | RustCrypto (`ml-kem`, `ml-dsa`, `slh-dsa`, `rsa`, `p256`, `p384`, `aes`, `sha2`, `sha3`) |
| Build toolchain | Emscripten SDK + CMake + cross-compiled OpenSSL | `cargo build --target wasm32-unknown-unknown` |
| WASM size | ~2 MB+ (OpenSSL linked) | **~1.3 MB** |
| C FFI | Native | None (pure Rust) |
| Pre-hash ML-DSA/SLH-DSA | Full (10 variants each) | Full (10 variants each) |

### API Parity — The "Disguise" Technique

Existing JavaScript consumers written against the C++ Emscripten build work without changing a single line of code. The Rust module uses `wasm-bindgen` with `js_name` to export functions with the same `_C_*` prefix that Emscripten generates:

```rust
#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    _hSession: u32,
    _pMechanism: *mut u8,
    // ...
) -> u32 { /* native Rust implementation */ }
```

Memory management (`_malloc`, `_free`), `HEAPU8`, `setValue`, and `getValue` are all provided by a thin JS shim that mirrors the Emscripten API surface.

### Supported PKCS#11 Functions

The Rust engine exports 65 PKCS#11 functions (49 fully implemented, 8 multi-part stubs, 8 admin stubs):

| Category | Functions |
| --- | --- |
| Info / Slot | `C_GetInfo`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo` |
| Session | `C_Initialize`, `C_Finalize`, `C_InitToken`, `C_OpenSession`, `C_CloseSession`, `C_Login`, `C_Logout`, `C_InitPIN`, `C_GetSessionInfo` |
| Key Generation | `C_GenerateKeyPair`, `C_GenerateKey` |
| KEM | `C_EncapsulateKey`, `C_DecapsulateKey` |
| Sign/Verify | `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify` |
| Message Sign/Verify | `C_MessageSignInit`, `C_SignMessage`, `C_MessageSignFinal`, `C_MessageVerifyInit`, `C_VerifyMessage`, `C_MessageVerifyFinal` |
| Encrypt/Decrypt | `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt` |
| Digest | `C_DigestInit`, `C_DigestUpdate`, `C_DigestFinal`, `C_Digest` |
| Object | `C_CreateObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` |
| Key Management | `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated` |
| Utility | `C_GenerateRandom` |
| Multi-part (stubs) | `C_SignUpdate`, `C_SignFinal`, `C_VerifyUpdate`, `C_VerifyFinal`, `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal` |
| Admin (stubs) | `C_SetPIN`, `C_CopyObject`, `C_GetObjectSize`, `C_SetAttributeValue`, `C_DigestKey`, `C_GetOperationState`, `C_SetOperationState`, `C_SeedRandom` |

Multi-part and admin stubs return `CKR_FUNCTION_NOT_SUPPORTED`. The browser playground uses single-shot operations only.

### Supported Algorithms

**Post-Quantum:**

- ML-KEM-512/768/1024 (keygen, encapsulate, decapsulate)
- ML-DSA-44/65/87 (keygen, sign, verify)
- SLH-DSA — all 12 parameter sets: SHA2/SHAKE x 128/192/256 x s/f (keygen, sign, verify)

**Classical:**

- RSA (PKCS#1 v1.5, OAEP, PSS — keygen + sign/verify)
- ECDSA P-256/P-384 (keygen, sign, verify) — including ECDSA-SHA3-224/256/384/512
- Ed25519 (keygen, sign, verify)
- ECDH P-256 + X25519 (key agreement via `C_DeriveKey`)
- AES-128/256 (GCM, CBC-PAD, CTR, Key Wrap, Key Wrap with Padding, Authenticated Wrap/Unwrap)
- SHA-256/384/512, SHA3-256/512 (digest)
- HMAC-SHA256/384/512, HMAC-SHA3-256/512
- HKDF (RFC 5869), PBKDF2 (`CKM_PKCS5_PBKD2`), SP 800-108 Counter/Feedback KDF

> **Note:** RSA-SHA3 variants (`CKM_RSA_SHA3_*_PKCS`, `CKM_RSA_SHA3_*_PKCS_PSS`) and ECDH1 with X9.63 KDF are C++ engine only.

**62 mechanisms** registered in `C_GetMechanismList` — 100% have implementations.

### PKCS#11 v3.2 Compliance Enforcement

The Rust engine enforces PKCS#11 v3.2 capability attributes on all operations:

| Check | Return Code | Enforcement Point |
| --- | --- | --- |
| `CKA_SIGN` on private key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_SignInit` |
| `CKA_VERIFY` on public key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_VerifyInit` |
| `CKA_ENCRYPT` on key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_EncryptInit` |
| `CKA_DECRYPT` on key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_DecryptInit` |
| `CKA_WRAP` on wrapping key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_WrapKey` |
| `CKA_UNWRAP` on unwrapping key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_UnwrapKey` |
| `CKA_DERIVE` on base key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_DeriveKey` |
| `CKA_EXTRACTABLE` on wrapped key | `CKR_KEY_UNEXTRACTABLE` | `C_WrapKey` |
| `CKA_SENSITIVE` / `!CKA_EXTRACTABLE` | `CK_UNAVAILABLE_INFORMATION` | `C_GetAttributeValue` (blocks `CKA_VALUE`) |

Generated private keys default to `CKA_SENSITIVE=true`. `C_DestroyObject` cleans up stale operation state to prevent use-after-free on destroyed keys.

### Rust Crate Dependencies

From `rust/Cargo.toml`:

| Crate | Purpose |
| --- | --- |
| `ml-kem` 0.2.3 | FIPS 203 key encapsulation |
| `ml-dsa` =0.1.0-rc.7 | FIPS 204 digital signatures |
| `slh-dsa` =0.2.0-rc.4 | FIPS 205 hash-based signatures |
| `rsa` 0.9 | RSA PKCS#1 / OAEP / PSS |
| `p256`, `p384` 0.13 | NIST curve ECDSA + ECDH |
| `ed25519-dalek` 2.1 | Ed25519 signatures |
| `x25519-dalek` 2.0 | X25519 key agreement |
| `aes` + `aes-gcm` + `cbc` + `aes-kw` | AES modes |
| `sha2`, `sha3`, `hmac` | Digest and MAC |
| `wasm-bindgen` 0.2.92 | WASM ↔ JS bridge |
| `getrandom` 0.2 (js feature) | Browser-compatible CSPRNG |

### Building the Rust Engine

```bash
# Prerequisites: Rust toolchain + wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build
cd rust
wasm-pack build --target web --release

# Output: rust/pkg/
#   softhsmrustv3_bg.wasm  (~1.3 MB)
#   softhsmrustv3.js       (JS bindings)
#   softhsmrustv3.d.ts     (TypeScript types)
```

> **Note:** `wasm-opt` is disabled in `Cargo.toml` because the PQC crates use bulk-memory WebAssembly instructions (`memory.copy`, `memory.fill`) that `wasm-opt` does not yet support. V8 (Chrome/Node.js) handles these natively.

### Testing

```bash
# Unit test (native, not WASM)
cd rust
cargo test

# Integration test — Rust engine standalone
node rust/test_harness.js

# Parity test — C++ vs Rust cross-engine verification
# Generates keys in one engine, operates in the other, verifies match
node tests/parity-wasm.mjs
```

The parity test (`tests/parity-wasm.mjs`) performs cross-engine verification:

1. **ML-KEM:** Rust generates keypair -> C++ encapsulates -> Rust decapsulates -> shared secrets must match
2. **ML-DSA:** C++ generates keypair + signs message -> Rust imports public key + verifies signature

### Architecture

```text
rust/
  Cargo.toml           # Dependencies, wasm-pack config, release profile
  src/
    lib.rs             # All PKCS#11 functions (~3,900 lines)
  pkg/                 # wasm-pack output (generated)
    softhsmrustv3_bg.wasm
    softhsmrustv3.js
    softhsmrustv3.d.ts
  test_harness.js      # Standalone integration test
  tests/
    pqc_api_test.rs    # Native Rust unit tests
tests/
  parity-wasm.mjs      # Cross-engine C++ ↔ Rust parity verification
softhsmrustv3design.md  # Detailed architecture design document
```

Internal state uses thread-local `RefCell<HashMap<u32, HashMap<u32, Vec<u8>>>>` for the object store (handle → attribute map), with monotonically incrementing `AtomicU32` handles returned to JS callers. Session handles are also unique via an atomic counter. All cryptographic operations execute entirely within WASM linear memory, isolated from the JavaScript heap.

## Known Limitations

- **Stateful hash-based signatures** (HSS, XMSS): Not implemented — these require persistent state management outside the scope of a software HSM.
- **Single-threaded**: The WASM target is single-threaded (no SharedArrayBuffer worker pool).
- **Non-persistent token**: Token state is in-memory only and does not survive WASM module reload.

## Roadmap

- [x] Phase 0: Import SoftHSM2 + PKCS#11 v3.2 headers + strip legacy ([#1](https://github.com/pqctoday/softhsmv3/issues/1))
- [x] Phase 1: OpenSSL 3.x API migration ([#2](https://github.com/pqctoday/softhsmv3/issues/2))
- [x] Phase 2: ML-DSA support ([#3](https://github.com/pqctoday/softhsmv3/issues/3))
- [x] Phase 3: ML-KEM + C_EncapsulateKey/C_DecapsulateKey ([#4](https://github.com/pqctoday/softhsmv3/issues/4))
- [x] Phase 4: Emscripten WASM build ([#5](https://github.com/pqctoday/softhsmv3/issues/5))
- [x] Phase 5: npm package `@pqctoday/softhsm-wasm` ([#6](https://github.com/pqctoday/softhsmv3/issues/6))
- [x] Phase 6: PQC Timeline App integration ([#7](https://github.com/pqctoday/softhsmv3/issues/7))
- [x] Phase 7: PKCS#11 v3.2 compliance gaps
  - [x] `C_GetInterfaceList` / `C_GetInterface` ([#8](https://github.com/pqctoday/softhsmv3/issues/8))
  - [x] `CKK_ML_DSA` + `CKM_ML_DSA*` mechanisms ([#12](https://github.com/pqctoday/softhsmv3/issues/12))
  - [x] `CKA_PARAMETER_SET` — PQC variant selection ([#11](https://github.com/pqctoday/softhsmv3/issues/11))
  - [x] `C_SignMessage` / `C_VerifyMessage` one-shot message signing ([#10](https://github.com/pqctoday/softhsmv3/issues/10))
  - [x] `CKK_SLH_DSA` + `CKM_SLH_DSA*` mechanisms ([#13](https://github.com/pqctoday/softhsmv3/issues/13))
  - [x] `CKK_ML_KEM` + `CKM_ML_KEM*` mechanisms ([#14](https://github.com/pqctoday/softhsmv3/issues/14))
  - [x] `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` attributes ([#15](https://github.com/pqctoday/softhsmv3/issues/15))
  - [x] `CKM_HASH_SLH_DSA*` — 11 pre-hash SLH-DSA variants ([#16](https://github.com/pqctoday/softhsmv3/issues/16))
  - [x] `C_SignMessageBegin` / `C_SignMessageNext` / `C_VerifyMessageBegin` / `C_VerifyMessageNext` ([#17](https://github.com/pqctoday/softhsmv3/issues/17))
  - [x] Message Encrypt/Decrypt API — AES-GCM per-message AEAD (10 functions) ([#18](https://github.com/pqctoday/softhsmv3/issues/18))
  - [x] `C_VerifySignatureInit` / `C_VerifySignature` — pre-bound verification ([#19](https://github.com/pqctoday/softhsmv3/issues/19))
  - [x] `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` ([#20](https://github.com/pqctoday/softhsmv3/issues/20))
  - [x] `C_LoginUser` / `C_SessionCancel` — v3.0 session management ([#21](https://github.com/pqctoday/softhsmv3/issues/21))
  - [x] `C_VerifySignatureFinal` / `C_VerifySignatureUpdate` multi-part pre-bound verify ([#22](https://github.com/pqctoday/softhsmv3/issues/22))
  - [x] `CKM_HKDF_DERIVE` — HMAC-based KDF (RFC 5869) via OpenSSL EVP HKDF
  - [x] `CKM_SP800_108_COUNTER_KDF` / `CKM_SP800_108_FEEDBACK_KDF` — NIST SP 800-108 counter and feedback KBKDF
  - [x] `CKM_ECDH1_COFACTOR_DERIVE` — cofactor ECDH via `EVP_PKEY_CTX_set_ecdh_cofactor_mode`
- [x] Phase 8: Pure-Rust WASM engine (`rust/`) — drop-in parity with C++ Emscripten build
- [x] Phase 9: PKCS#11 v3.2 compliance audit — C++ and Rust engines
  - [x] C++: `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` defaults fixed (Table 18); explicit set in `C_GenerateKeyPair`
  - [x] Rust: `SUPPORTED_MECHS` expanded 31→62; `CKA_SIGN/VERIFY/ENCRYPT/DECRYPT` enforcement in `*Init`
  - [x] Rust: `AtomicU32` unique session handles; `CKA_SENSITIVE=true` for private keys
  - [x] Rust: `C_DestroyObject` state cleanup; `C_DeriveKey` `CKA_DERIVE` check
  - [x] Rust: output keys from KEM/derive carry proper attributes (`CKA_EXTRACTABLE`, `CKA_CLASS`, etc.)
  - [x] Rust: 10 admin function stubs + 8 multi-part stubs (63 total exports)
- [x] Phase 10: SHA-3 variants, PBKDF2, 5G KDF, key wrapping completeness
  - [x] C++: `CKM_ECDSA_SHA3_224/256/384/512` — ECDSA with SHA-3 hash
  - [x] C++: `CKM_RSA_SHA3_224/256/384/512_PKCS` and `_PKCS_PSS` — RSA PKCS#1 v1.5 and PSS with SHA-3
  - [x] C++ + Rust: `CKM_PKCS5_PBKD2` — PBKDF2 key derivation; HMAC-SHA{1/224/256/384/512} PRF; BIP39 / SLIP-0010
  - [x] C++: `CKD_SHA{1,256,384,512}_KDF` on `CKM_ECDH1_DERIVE` — X9.63 KDF for 5G SUCI deconcealment (TS 33.501 §6.12.2)
  - [x] C++: `CKM_AES_KEY_WRAP_PAD` registered in `prepareSupportedMechanisms()`
  - [x] Rust: `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` — AES-GCM authenticated key wrap (PKCS#11 v3.2 §5.18.6–7)
  - [x] Rust: `C_WrapKey` extended to accept `CKM_RSA_PKCS_OAEP` for indirect RSA+KEK wrapping
  - [x] Rust: `CKM_AES_KEY_WRAP_KWP` case added to `C_GetMechanismInfo`
  - [x] Rust: 65 total PKCS#11 exports (49 implemented, 8 multi-part stubs, 8 admin stubs)

## Building (Native)

```bash
# Requires OpenSSL >= 3.6 (for ML-DSA and SLH-DSA EVP support)
mkdir build && cd build
cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
make
make check
```

## Building (WASM — C++/Emscripten)

```bash
# Requires Emscripten SDK + OpenSSL 3.6 cross-compiled for WASM
mkdir build-wasm && cd build-wasm
emcmake cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
emmake make
```

## Building (WASM — Rust)

```bash
# Requires Rust toolchain + wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd rust
wasm-pack build --target web --release
# Output: rust/pkg/softhsmrustv3_bg.wasm (~336 KB)
```

## References

- [PKCS#11 v3.2 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 v3.2 pkcs11t.h](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2/pkcs11t.h) — canonical constant values
- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [OpenSSL 3.6 ML-KEM Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-KEM/)
- [OpenSSL 3.6 ML-DSA Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-DSA/)
- [RustCrypto Organization](https://github.com/RustCrypto) — `ml-kem`, `ml-dsa`, `slh-dsa`, `rsa`, `aes` crates
- [wasm-bindgen](https://rustwasm.github.io/docs/wasm-bindgen/) — Rust ↔ JS WASM bridge
- [Original SoftHSM2](https://github.com/softhsm/SoftHSMv2)

## License

BSD-2-Clause (same as SoftHSM2). See [LICENSE](LICENSE).

## Acknowledgments

This project is a fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) by the OpenDNSSEC project. PQC implementation references Mozilla NSS (Bug 1965329) and Thales Luna HSM documentation.

Maintained by [PQC Today](https://pqctoday.com).
