# SoftHSMv3 / `@pqctoday/softhsm-wasm`

A modernized fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) with **OpenSSL 3.x**, **PKCS#11 v3.2**, and **post-quantum cryptography** support — compiled to WebAssembly for use in browsers and Node.js.

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
| GOST/DES/DSA/DH | Included | Removed (focused codebase) |
| WASM build | Not supported | **Emscripten target** |
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

### Key Derivation

```c
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

## Building (Native)

```bash
# Requires OpenSSL >= 3.6 (for ML-DSA and SLH-DSA EVP support)
mkdir build && cd build
cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
make
make check
```

## Building (WASM)

```bash
# Requires Emscripten SDK + OpenSSL 3.6 cross-compiled for WASM
mkdir build-wasm && cd build-wasm
emcmake cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
emmake make
```

## References

- [PKCS#11 v3.2 Specification (CSD01)](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.html)
- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [OpenSSL 3.6 ML-KEM Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-KEM/)
- [OpenSSL 3.6 ML-DSA Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-DSA/)
- [Original SoftHSM2](https://github.com/softhsm/SoftHSMv2)

## License

BSD-2-Clause (same as SoftHSM2). See [LICENSE](LICENSE).

## Acknowledgments

This project is a fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) by the OpenDNSSEC project. PQC implementation references Mozilla NSS (Bug 1965329) and Thales Luna HSM documentation.

Maintained by [PQC Today](https://pqctoday.com).
