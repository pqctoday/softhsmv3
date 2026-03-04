# PKCS#11 v3.2 Compliance Gap Analysis — softhsmv3 (v5)

**Updated:** 2026-03-04 (v5 — 5G Security gaps resolved)
**Baseline:** Post-Phase-7 + G-DA1 + G-DA2 + G-5G1 + G-5G2 + G-5G3 — all tracked gaps resolved
**Spec reference:** OASIS PKCS#11 v3.2 CSD01 (<http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/>)
**Prior baseline (v4):** Post-Phase-7 (2026-03-04) — G1–G6 resolved; G-DA1/G-DA2 identified via
Digital Assets module crypto audit.

---

## Executive Summary

All NIST PQC finalists (ML-KEM, ML-DSA, SLH-DSA) are fully implemented.
All v3.2 KEM functions (`C_EncapsulateKey`, `C_DecapsulateKey`) are implemented.
All v3.0/v3.2 message sign/verify functions are implemented (one-shot and streaming).
All v3.2 pre-hash mechanisms for both ML-DSA and SLH-DSA are registered and dispatched.
All v3.2 additions tracked as G1–G6 are implemented.
**v4:** `CKM_PKCS5_PBKD2` (G-DA1) and `CKM_ECDSA_SHA3_224/256/384/512` (G-DA2)
implemented — completing the Digital Assets module crypto requirements.
**NEW (v5):** `CKM_AES_CTR` (G-5G1), `CKD_SHA256_KDF` on `CKM_ECDH1_DERIVE` (G-5G2),
and `CKM_HKDF_DERIVE` (G-5G3) implemented — completing the 5G Security module PKCS#11 path
for SUCI deconcealment (3GPP TS 33.501 §6.12.2).

| Dimension | Remaining open | Notes |
| --- | --- | --- |
| C_* function stubs (in scope) | 0 | All G1–G6 + G-DA1/G-DA2 + G-5G1/5G2/5G3 resolved |
| CKM_* mechanisms (in scope) | 0 | AES-CTR, HKDF, X9.63 KDF support added |
| Out-of-scope stubs | 3 | Async (G7), Recovery/Combined ops (G8) |
| Out-of-scope mechanisms | 1 | CKM_RIPEMD160 (WASM `no-module` constraint, G9) |

---

## 1. Resolved Gaps (v2 list — G1–G6)

All of the following were open in the v2 baseline and are now confirmed implemented.

### 1.1 G1 — CKM_HASH_SLH_DSA* — 13 pre-hash mechanism variants ✓ RESOLVED

All 13 SLH-DSA pre-hash mechanisms are:

- **Registered** in `prepareSupportedMechanisms()` (`src/lib/SoftHSM_slots.cpp:414–427`)
- **Dispatched** in `AsymSignInit()` and `AsymVerifyInit()` (`src/lib/SoftHSM_sign.cpp`, `HASH_SLHDSA_CASE` macros)
- **Handled** in `OSSLSLHDSA.cpp` (`AsymMech::HASH_SLHDSA` through `HASH_SLHDSA_SHAKE256`)
- **Defined** in `AsymmetricAlgorithm.h` enum

Full parity with ML-DSA pre-hash (12 hash variants each, plus 1 generic = 13 total for each).

Playground integration also resolved: `softhsm.ts` now exports `CKM_HASH_SLH_DSA_*` constants
and `hsm_slhdsaSign`/`hsm_slhdsaVerify` accept `opts.preHash` for all 10 hash variants.

### 1.2 G2 — Streaming message sign/verify — 4 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_SignMessageBegin` | `SoftHSM_sign.cpp` | 2461 |
| `C_SignMessageNext` | `SoftHSM_sign.cpp` | 2484 |
| `C_VerifyMessageBegin` | `SoftHSM_sign.cpp` | 2528 |
| `C_VerifyMessageNext` | `SoftHSM_sign.cpp` | 2549 |

### 1.3 G3 — Message Encrypt/Decrypt API — 10 functions ✓ RESOLVED

All 10 functions implemented in `src/lib/SoftHSM_cipher.cpp` (from line 1299).
`C_MessageEncryptInit` at line 1529. State machine uses `SESSION_OP_MESSAGE_ENCRYPT` (0x15).

### 1.4 G4 — C_VerifySignature* — 4 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_VerifySignatureInit` | `SoftHSM_sign.cpp` | 2595 |
| `C_VerifySignature` | `SoftHSM_sign.cpp` | (follows) |
| `C_VerifySignatureUpdate` | `SoftHSM_sign.cpp` | (follows) |
| `C_VerifySignatureFinal` | `SoftHSM_sign.cpp` | (follows) |

State: `SESSION_OP_VERIFY_SIGNATURE` (0x19) defined in `session_mgr/Session.h:65`.

### 1.5 G5 — Authenticated key wrapping — 2 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_WrapKeyAuthenticated` | `SoftHSM_keygen.cpp` | 1568 |
| `C_UnwrapKeyAuthenticated` | `SoftHSM_keygen.cpp` | (follows) |

### 1.6 G6 — v3.0 session management — 2 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_LoginUser` | `SoftHSM_sessions.cpp` | 238 |
| `C_SessionCancel` | `SoftHSM_sessions.cpp` | 250 |

---

## 1.5 Digital Assets Module Gaps (v4 additions — G-DA1, G-DA2)

Identified via audit of the Digital Assets learning module crypto operations cross-referenced
against PKCS#11 v3.2 spec. All Digital Assets crypto was mapped; two mechanisms were missing.

### 1.7 G-DA1 — `CKM_PKCS5_PBKD2` — PBKDF2 key derivation ✓ RESOLVED

**Need:** BIP39 mnemonic → 64-byte seed derivation (`PBKDF2-HMAC-SHA512`, 2048 iterations).
**PKCS#11 v3.2:** `§5.7.3.1` — `CKM_PKCS5_PBKD2` (`0x000003b0`), uses `CK_PKCS5_PBKD2_PARAMS2`.

| Component | File | Change |
| --- | --- | --- |
| Mechanism registry | `SoftHSM_slots.cpp:356` | Added `CKM_PKCS5_PBKD2` with `CKF_DERIVE` |
| C_DeriveKey handler | `SoftHSM_keygen.cpp:1908` | PBKDF2 early-return path (no base key) |
| OpenSSL call | `SoftHSM_keygen.cpp` | `PKCS5_PBKDF2_HMAC()` — maps `CKP_PKCS5_PBKD2_HMAC_{SHA1,SHA224,SHA256,SHA384,SHA512}` |
| Playground constant | `softhsm.ts:1103` | `CKM_PKCS5_PBKD2 = 0x3b0` + `CKP_PKCS5_PBKD2_HMAC_*` |
| Playground helper | `softhsm.ts:1669` | `hsm_pbkdf2(M, hSession, password, salt, iterations, keyLen, prf?)` |
| Learning module | `hsmConstants.ts` | Added to `PKCS11_MECHANISMS` array |

**PRFs supported:** SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (default: SHA-512 for BIP39).

### 1.8 G-DA2 — `CKM_ECDSA_SHA3_224/256/384/512` — ECDSA with SHA-3 prehash ✓ RESOLVED

**Need:** PKCS#11 v3.2 §6.3 spec completeness. SHA-3 hash support already existed; only
  registration and dispatch were missing.

| Component | File | Change |
| --- | --- | --- |
| Enum values | `AsymmetricAlgorithm.h:98` | Added `ECDSA_SHA3_{224,256,384,512}` |
| OpenSSL dispatch | `OSSLECDSA.cpp:108,245` | Added `EVP_sha3_{224,256,384,512}()` in `sign()` + `verify()` |
| Mechanism registry | `SoftHSM_slots.cpp:391` | Registered 4 `CKM_ECDSA_SHA3_*` mechanisms |
| Sign dispatch | `SoftHSM_sign.cpp:670` | Added 4 cases in `AsymSignInit()` |
| Verify dispatch | `SoftHSM_sign.cpp:1670` | Added 4 cases in `AsymVerifyInit()` |
| Playground constants | `softhsm.ts:1091` | `CKM_ECDSA_SHA3_{224,256,384,512} = 0x1047–0x104a` |
| Learning module | `hsmConstants.ts` | Added 4 entries to `PKCS11_MECHANISMS` |

**Note:** `CKM_RIPEMD160` is **not** implemented — see G11 below for rationale.

---

## 1.9 5G Security Module Gaps (v5 additions — G-5G1, G-5G2, G-5G3)

Identified via audit of the 5G Security learning module (SUCI deconcealment + MILENAGE) crypto
operations cross-referenced against PKCS#11 v3.2 and softhsmv3 coverage.

**Context:** 5G NR SUCI (3GPP TS 33.501 §6.12.2) uses ECIES-based subscriber privacy:
Profile A (X25519 + ANSI X9.63-SHA256 KDF + AES-128-CTR + HMAC-SHA256),
Profile B (P-256 + same), Profile C (ML-KEM-768 hybrid + AES-256-CTR + HMAC-SHA3-256).
MILENAGE (TS 35.206) uses AES-128-ECB for f1–f5. KAUSF uses HMAC-SHA-256.

### 1.9 G-5G1 — `CKM_AES_CTR` — AES Counter mode ✓ RESOLVED

**Need:** SUCI MSIN encryption for Profiles A/B (AES-128-CTR) and Profile C (AES-256-CTR).
`CKM_AES_CTR` was already registered and dispatched in softhsmv3 (slots.cpp:380, cipher.cpp:59,130,746)
but was missing from the app-side WASM wrapper — app-only fix, no WASM rebuild required.

**`CK_AES_CTR_PARAMS`** (20 bytes): `ulCounterBits`[4] + `cb[16]` counter/IV block. For SUCI:
`ulCounterBits = 128`, `cb = 00...00` (zero IV per 3GPP spec).

| Component | File | Change |
| --- | --- | --- |
| Constants | `softhsm.ts:~1113` | `CKM_AES_ECB = 0x1081`, `CKM_AES_CTR = 0x1086` |
| Helper | `softhsm.ts` | `hsm_aesCtrEncrypt(M, hSession, key, ctrIv, counterBits, data)` |
| Helper | `softhsm.ts` | `hsm_aesCtrDecrypt(M, hSession, key, ctrIv, counterBits, data)` |
| Learning module | `hsmConstants.ts` | Added `ckm-aes-ecb` and `ckm-aes-ctr` entries |

### 1.10 G-5G2 — `CKD_SHA256_KDF` on `CKM_ECDH1_DERIVE` — ANSI X9.63 KDF ✓ RESOLVED

**Need:** SUCI Profiles A/B key derivation after ECDH — `K = SHA256(Z ∥ counter ∥ SharedInfo)`
(ANSI X9.63, 3GPP TS 33.501 §C.3). Maps to `CKM_ECDH1_DERIVE` with `kdf = CKD_SHA256_KDF`
in `CK_ECDH1_DERIVE_PARAMS`. Previously softhsmv3 rejected any `kdf != CKD_NULL`.

**OpenSSL implementation:** `EVP_KDF_fetch(NULL, "X963KDF", NULL)` + `EVP_KDF_derive()` with
`OSSL_KDF_PARAM_DIGEST`, `OSSL_KDF_PARAM_SECRET`, `OSSL_KDF_PARAM_INFO` (SharedInfo).
KDF confirmed present in WASM libcrypto.a via `ossl_kdf_x963_kdf_functions` symbol.
Used non-deprecated OpenSSL 3.x EVP_KDF API (not `ECDH_KDF_X9_62` which is OSSL_DEPRECATEDIN_3_0).

| Component | File | Change |
| --- | --- | --- |
| Validation fix (ECDH) | `SoftHSM_keygen.cpp:deriveECDH()` | Accept `CKD_SHA{1,256,384,512}_KDF`; reject only unknown KDFs |
| KDF dispatch (ECDH) | `SoftHSM_keygen.cpp:deriveECDH()` | After `secret->getKeyBits()`: apply `EVP_KDF X963KDF` if `kdf != CKD_NULL` |
| Validation fix (EdDSA/X25519) | `SoftHSM_keygen.cpp:deriveEDDSA()` | Same as ECDH |
| KDF dispatch (EdDSA/X25519) | `SoftHSM_keygen.cpp:deriveEDDSA()` | Same as ECDH |
| New includes | `SoftHSM_keygen.cpp:79` | `<openssl/kdf.h>`, `<openssl/core_names.h>`, `<openssl/params.h>` |
| File-scope helpers | `SoftHSM_keygen.cpp:89` | `ckdToDigestName()`, `ckmToDigestName()` static functions |
| Constants | `softhsm.ts` | `CKD_SHA1_KDF=0x2`, `CKD_SHA256_KDF=0x6`, `CKD_SHA384_KDF=0x7`, `CKD_SHA512_KDF=0x8` |
| API update | `softhsm.ts:hsm_ecdhDerive()` | New optional params: `kdf`, `sharedData`, `keyLen` |

**KDFs supported:** SHA-1, SHA-256, SHA-384, SHA-512 via `CKD_SHA{1,256,384,512}_KDF`.
**Note:** `checkValue = false` applied when KDF is active — KCV not meaningful for KDF-derived keys.

### 1.11 G-5G3 — `CKM_HKDF_DERIVE` — HMAC-based KDF ✓ RESOLVED

**Need:** PKCS#11 v3.0 standard HKDF mechanism for hybrid key combination (SUCI Profile C:
`SHA256(Z_ecdh ∥ Z_kem) → KDF`), TLS 1.3 key schedule, Signal Protocol.
`CKM_HKDF_DERIVE = 0x0000402a`. Not present in softhsmv3 prior to this fix.

**OpenSSL implementation:** `EVP_KDF_fetch(NULL, "HKDF", NULL)` + `EVP_KDF_derive()` with
`OSSL_KDF_PARAM_MODE` (integer: `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` etc.),
`OSSL_KDF_PARAM_DIGEST`, `OSSL_KDF_PARAM_KEY` (IKM from base key), `OSSL_KDF_PARAM_SALT`,
`OSSL_KDF_PARAM_INFO`. Base key value retrieved via `key->getByteStringValue(CKA_VALUE)`.

| Component | File | Change |
| --- | --- | --- |
| Mechanism registry | `SoftHSM_slots.cpp:358` | `CKM_HKDF_DERIVE` registered |
| C_DeriveKey handler | `SoftHSM_keygen.cpp:2194` | HKDF block between ECDH and symmetric derive dispatchers |
| Constant | `softhsm.ts` | `CKM_HKDF_DERIVE = 0x402a`, `CKF_HKDF_SALT_NULL = 0x1`, `CKF_HKDF_SALT_DATA = 0x2` |
| Helper | `softhsm.ts` | `hsm_hkdf(M, hSession, baseKeyHandle, prf, bExtract, bExpand, salt?, info?, keyLen?)` |
| Learning module | `hsmConstants.ts` | Added `ckm-hkdf-derive` entry |

**PRFs supported:** `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512`, `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512`.
**Salt types supported:** `CKF_HKDF_SALT_NULL`, `CKF_HKDF_SALT_DATA`. (`CKF_HKDF_SALT_KEY` — not supported.)
**Modes:** Extract-and-Expand, Extract-only, Expand-only (driven by `bExtract`/`bExpand` flags).

**`CK_HKDF_PARAMS` layout in WASM (32 bytes):**
- Offsets 0–1: `bExtract`, `bExpand` (CK_BBOOL, 1 byte each)
- Offsets 2–3: padding (C struct alignment)
- Offsets 4–31: `prfHashMechanism`, `ulSaltType`, `pSalt`, `ulSaltLen`, `hSaltKey`, `pInfo`, `ulInfoLen` (4 bytes each)

---

## 2. Previously Resolved Gaps (v1 list, Phase 0–6)

All 50 gaps from the v1 baseline remain resolved. Closed GitHub issues: #8–#22.
See v2 document section §1 for the complete list.

---

## 3. Explicitly Out of Scope

### 3.1 G7 — Async operations

`C_AsyncComplete` (`main.cpp:1812`), `C_AsyncGetID` (`main.cpp:1818`), `C_AsyncJoin` (`main.cpp:1824`)

Return `CKR_FUNCTION_NOT_SUPPORTED`. Requires `CKF_ASYNC_SESSION` mode and thread-safe
promise-based state machine. No PQC tooling requires this. Omission is acceptable per
PKCS#11 v3.2 §3.4 which marks async as optional when not advertised.

### 3.2 G8 — Recovery and combined operations

`C_SignRecoverInit`, `C_SignRecover` (`SoftHSM_sign.cpp:1181, 1194`)
`C_VerifyRecoverInit`, `C_VerifyRecover` (`SoftHSM_sign.cpp:2790, 2803`)
`C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`
(`SoftHSM_sign.cpp:2818–2875`)

Return `CKR_FUNCTION_NOT_SUPPORTED`. Optional combined/recovery operations from PKCS#11 v2.0.
SoftHSM2 v2.7.0 also omits them. No PQC algorithm requires them.

### 3.3 G9 — Session validation flags (v3.2)

`C_GetSessionValidationFlags` (`main.cpp:1802`) returns `CKR_FUNCTION_NOT_SUPPORTED`.
New in v3.2 §5.22. Not required for PQC operations.

### 3.4 G10 — Stateful hash-based signatures (HSS/XMSS/XMSSMT)

`CKK_HSS`, `CKK_XMSS`, `CKK_XMSSMT` and their mechanisms are defined in PKCS#11 v3.2 headers
but are out of scope because OpenSSL 3.x does not natively support these algorithms.
Would require liboqs integration or a specialized provider — contradicts the OpenSSL-only
backend design of softhsmv3. Deferred pending OpenSSL native support.

### 3.5 G11 — Session-state serialization

`C_GetOperationState` and `C_SetOperationState` (`SoftHSM_sessions.cpp:125, 140`)
return `CKR_FUNCTION_NOT_SUPPORTED`. Not relevant for PQC operations.

### 3.6 G-DA-X — CKM_RIPEMD160 (WASM build constraint)

`CKM_RIPEMD160` (`0x00000240`) — defined in PKCS#11 v3.2 (marked "Historical").

**Blocker:** The OpenSSL WASM build (`scripts/build-openssl-wasm.sh`) uses `no-module` which
disables the OpenSSL legacy provider. RIPEMD-160 lives in the legacy provider and is not
accessible in the WASM build. Enabling it would require adding `enable-legacy` to the WASM
build flags and verifying size impact (~+50 KB estimated). The Digital Assets module currently
computes Bitcoin HASH160 via `@noble/hashes/ripemd160` client-side.

**Decision:** Deferred. No `no-module` removal planned until WASM size budget allows.

---

## 4. OpenSSL 3.6 Algorithm Support Reference

All in-scope algorithms are supported natively via EVP_PKEY in OpenSSL 3.3+ (3.6 for full set).

| Algorithm | Parameter sets | EVP_PKEY name pattern | Minimum OpenSSL |
| --- | --- | --- | --- |
| ML-KEM | 512, 768, 1024 | `"mlkem512"`, `"mlkem768"`, `"mlkem1024"` | 3.3 |
| ML-DSA | 44, 65, 87 | `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"` | 3.3 |
| SLH-DSA | 12 variants | `"slh-dsa-sha2-128s"` … `"slh-dsa-shake-256f"` | 3.5 (full in 3.6) |

Pre-hash mode: `OSSL_PARAM_utf8_string("digest", "sha256")` pattern (same for ML-DSA and SLH-DSA).
SHAKE XOF pre-hash: verified working via `"shake128"`/`"shake256"` digest names in OpenSSL 3.6.

---

## 5. Playground Integration Status (pqc-timeline-app)

As of 2026-03-04 (v4):

| Feature | `softhsm.ts` | SoftHsmTab UI |
| --- | --- | --- |
| ML-KEM key gen, encap, decap | ✓ | ✓ |
| ML-DSA key gen, pure sign/verify | ✓ | ✓ |
| ML-DSA pre-hash (all 10 variants) | ✓ (expanded) | ✓ (FilterDropdown, all 10 variants) |
| SLH-DSA key gen, pure sign/verify | ✓ | ✓ |
| SLH-DSA pre-hash (all 10 variants) | ✓ (new) | ✓ (FilterDropdown, all 10 variants) |
| RSA, ECDSA, EdDSA | ✓ | ✓ |
| ECDSA-SHA3-224/256/384/512 (G-DA2) | ✓ constants | Not wired (spec completeness) |
| AES-GCM, AES-CMAC, key wrap | ✓ | ✓ |
| PBKDF2 / CKM_PKCS5_PBKD2 (G-DA1) | ✓ `hsm_pbkdf2()` helper | Not wired (low priority) |
| Streaming sign/verify (G2) | softhsmv3 ✓ | Not wired (low priority) |
| Per-message encrypt/decrypt (G3) | softhsmv3 ✓ | Not wired (low priority) |
| Pre-bound signature verify (G4) | softhsmv3 ✓ | Not wired (low priority) |
| Authenticated key wrap (G5) | softhsmv3 ✓ | Not wired (low priority) |
