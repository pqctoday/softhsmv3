# How to Test SoftHSMv3

This guide covers the full testing workflow for SoftHSMv3: building the
library, running the CppUnit p11test suite, and running the standalone
`pqc_validate` program that exercises every PKCS#11 v3.2 mechanism
supported by OpenSSL 3.6.0.

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Build](#2-build)
3. [Initialize a Test Token](#3-initialize-a-test-token)
4. [CppUnit p11test Suite](#4-cppunit-p11test-suite)
5. [pqc_validate — Algorithm Validation](#5-pqc_validate--algorithm-validation)
6. [JSON Result Files](#6-json-result-files)
7. [Phase-by-Phase Expectations](#7-phase-by-phase-expectations)
8. [Debugging Tips](#8-debugging-tips)
9. [CI Integration](#9-ci-integration)

---

## 1. Prerequisites

### macOS

```bash
brew install openssl@3 cmake cppunit
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export PATH="$OPENSSL_ROOT_DIR/bin:$PATH"
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install build-essential cmake libssl-dev libcppunit-dev
```

### Minimum versions

| Dependency | Minimum | Notes |
|---|---|---|
| CMake | 3.16 | |
| OpenSSL | 3.3 | 3.5+ for SLH-DSA; 3.6.0 for full PQC scope |
| CppUnit | 1.15 | For p11test only |
| C++ compiler | C++17 | g++ 11+ or clang++ 14+ |

Check your versions:

```bash
cmake --version
openssl version
```

---

## 2. Build

All commands run from the **softhsmv3 repository root**.

### Debug build (recommended for testing)

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Release build

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Build output locations

| Artifact | Path |
|---|---|
| Shared library (macOS) | `build/src/lib/libsofthsmv3.dylib` |
| Shared library (Linux) | `build/src/lib/libsofthsmv3.so` |
| Static library | `build/src/lib/libsofthsmv3-static.a` |
| softhsm2-util CLI | `build/src/bin/util/softhsm2-util` |

> **Note**: The library is named `libsofthsmv3` (not `libsofthsm2`).
> Replace `.dylib` with `.so` on Linux throughout this document.

---

## 3. Initialize a Test Token

Before running either test suite you need a token slot with known PINs.

```bash
# Create a token named "pqctest" in slot 0
./build/src/bin/util/softhsm2-util \
    --init-token --slot 0 \
    --label "pqctest" \
    --so-pin 1234 \
    --pin 5678
```

Verify it was created:

```bash
./build/src/bin/util/softhsm2-util --show-slots
```

You should see a slot with label `pqctest` and status `Token is initialized`.

### Token directory

By default, SoftHSMv3 stores token data in the directory specified by
`softhsmv3.conf` (or the env var `SOFTHSM2_CONF`). The test suites set
this automatically. For manual testing, set:

```bash
export SOFTHSM2_CONF=/path/to/your/softhsmv3.conf
```

---

## 4. CppUnit p11test Suite

The CppUnit suite (`src/lib/test/`) tests the full PKCS#11 interface through
static linkage or a shared library. It exercises sessions, objects, tokens,
key generation, and cryptographic operations.

### Build p11test

```bash
# Rebuild with tests enabled
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Run all tests

```bash
cd build
make check
```

Or run the test binary directly:

```bash
cd build/src/lib/test
./p11test
```

Output is written to both stdout and `test-results.xml` (CppUnit XML format).

### Run a specific test class

```bash
./p11test SignVerifyTests
./p11test DigestTests
./p11test SymmetricAlgorithmTests
```

### Run a single test case

```bash
./p11test SignVerifyTests::testSignVerifyRSA
./p11test ObjectTests::testArrayAttribute
```

### Test against a shared library (external p11 module)

To test the built `.dylib`/`.so` as an external PKCS#11 module instead of
using static linkage:

```bash
# From build/src/lib/test/
make p11test_DEPENDENCIES= p11test_LDADD= \
    CPPFLAGS="-DP11_SHARED_LIBRARY=\\\"$(pwd)/../../lib/libsofthsmv3.dylib\\\"" \
    p11test
./p11test
```

### Available test classes

| Class | What it tests |
|---|---|
| `InitTests` | `C_Initialize`, `C_Finalize`, `C_GetInfo` |
| `InfoTests` | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo` |
| `SessionTests` | `C_OpenSession`, `C_CloseSession`, session states |
| `TokenTests` | Token init, PIN management |
| `UserTests` | `C_Login`, `C_Logout`, PIN changes |
| `ObjectTests` | Object create/destroy/find, attribute get/set |
| `DigestTests` | SHA-1/224/256/384/512 + SHA3 variants |
| `SymmetricAlgorithmTests` | AES-ECB/CBC/GCM/CTR/CMAC, HMAC |
| `SignVerifyTests` | RSA PKCS#1v1.5/PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA |
| `AsymEncryptDecryptTests` | RSA OAEP, ML-KEM |
| `AsymWrapUnwrapTests` | RSA wrap/unwrap, AES key wrap |
| `DeriveTests` | ECDH, X25519, X448 |
| `RandomTests` | `C_GenerateRandom` |
| `ForkTests` | Behavior across `fork()` (Linux only) |

---

## 5. pqc_validate — Algorithm Validation

`pqc_validate` is a standalone C++17 program (in `tests/`) that runs every
OpenSSL 3.6.0-supported mechanism through the PKCS#11 v3.2 interface, logs
structured results to JSON, and performs symmetric round-trip verification
with negative tamper tests on each operation.

### 5.1 Download nlohmann/json

```bash
curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
     -o tests/json.hpp
```

### 5.2 Compile

```bash
# From softhsmv3 root:
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/
```

On macOS with Homebrew OpenSSL:

```bash
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/ \
    -I$(brew --prefix openssl@3)/include
```

### 5.3 Run

```bash
# Minimal — auto-detects or initializes token
./pqc_validate ./build/src/lib/libsofthsmv3.dylib

# Linux
./pqc_validate ./build/src/lib/libsofthsmv3.so

# With explicit PINs and verbose hex output
./pqc_validate ./build/src/lib/libsofthsmv3.dylib \
    --so-pin 1234 --user-pin 5678 --verbose

# Custom ops file, results into /tmp
./pqc_validate ./build/src/lib/libsofthsmv3.dylib \
    --ops-file tests/pqc_validate_ops.json \
    --output-dir /tmp
```

### 5.4 Command-line options

| Option | Default | Description |
|---|---|---|
| `<library>` | (required) | Path to `libsofthsmv3.dylib` / `.so` |
| `--so-pin PIN` | `1234` | Security Officer PIN |
| `--user-pin PIN` | `5678` | User (application) PIN |
| `--ops-file PATH` | `tests/pqc_validate_ops.json` | Operations template |
| `--output-dir PATH` | `.` (cwd) | Directory for result JSON |
| `--verbose` | off | Print hex inputs/outputs per operation |

### 5.5 Console output

```
╔══ SoftHSMv3 PKCS#11 v3.2 Algorithm Validator ══╗
  Library:    ./build/src/lib/libsofthsmv3.dylib
  Ops file:   tests/pqc_validate_ops.json
  Output:     ./pqc_validate_03022026.json

══ rng-001 — C_GenerateRandom — 32 bytes ══
  ✓ C_GenerateRandom 32 bytes

══ hash-sha256-001 — SHA-256 Digest — NIST vector ("abc") ══
  ✓ SHA-256 Digest — NIST vector ("abc")

══ ml-kem-512-001 — ML-KEM-512 — encapsulate/decapsulate round-trip ══
  ⊘ SKIP: CKR_MECHANISM_INVALID — not yet implemented

╔══ Summary ══╗
  Total:   70
  Passed:  52
  Failed:  0
  Skipped: 18
  Output:  ./pqc_validate_03022026.json
```

### 5.6 Exit codes

| Code | Meaning |
|---|---|
| `0` | All tests passed or skipped; no failures |
| `1` | One or more tests failed |
| `2` | Bad arguments or cannot open library / ops file |

---

## 6. JSON Result Files

Each `pqc_validate` run produces one dated JSON file:

```
pqc_validate_03022026.json       ← first run on 2026-03-02
pqc_validate_03022026_r1.json    ← second run same day
pqc_validate_03022026_r2.json    ← third run, etc.
```

### Top-level structure

```json
{
  "schema_version": "1.0",
  "run_metadata": {
    "run_id": "pqc_validate_03022026",
    "started_at": "2026-03-02T10:23:44Z",
    "completed_at": "2026-03-02T10:25:01Z",
    "library_path": "./build/src/lib/libsofthsmv3.dylib",
    "token_slot": 0,
    "summary": { "total": 70, "passed": 52, "failed": 0, "skipped": 18 }
  },
  "operations": [
    {
      "id": "ml-kem-512-001",
      "category": "ML-KEM",
      "name": "ML-KEM-512 — encapsulate/decapsulate round-trip + tamper test",
      "result": {
        "status": "PASS",
        "timestamp": "2026-03-02T10:24:10.456Z",
        "duration_ms": 14,
        "inputs": {
          "parameter_set": "CKP_ML_KEM_512",
          "parameter_set_id": "0x00000001"
        },
        "outputs": {
          "ciphertext_len": 768,
          "secrets_match": true,
          "negative_tamper_ok": true
        },
        "error": null
      }
    }
  ]
}
```

### Status values

| Status | Meaning |
|---|---|
| `PASS` | Round-trip verified; negative test confirmed |
| `FAIL` | Test failed; inspect `error` field |
| `SKIP` | Mechanism returned `CKR_MECHANISM_INVALID` or `CKR_FUNCTION_NOT_SUPPORTED` |

SKIPs are expected and **do not count as failures** (exit code `0`).

---

## 7. Phase-by-Phase Expectations

### p11test (CppUnit)

| Phase | Tests expected to pass |
|---|---|
| Phase 0 | InitTests, InfoTests, SessionTests, TokenTests, UserTests, ObjectTests |
| Phase 1 | + DigestTests, RandomTests, SymmetricAlgorithmTests, AsymWrapUnwrapTests, DeriveTests, SignVerifyTests (RSA/ECDSA/EdDSA), AsymEncryptDecryptTests (RSA) |
| Phase 2 | + SignVerifyTests (ML-DSA) |
| Phase 3 | + AsymEncryptDecryptTests (ML-KEM) |
| Phase 4+ | + SLH-DSA variants |

### pqc_validate

| Phase | Classical | ML-DSA | ML-KEM | SLH-DSA | Expected exit |
|---|---|---|---|---|---|
| Phase 1 (EVP migration) | PASS | SKIP | SKIP | SKIP | `0` |
| Phase 2 (ML-DSA) | PASS | **PASS** | SKIP | SKIP | `0` |
| Phase 3 (ML-KEM) | PASS | PASS | **PASS** | SKIP | `0` |
| Phase 4+ (SLH-DSA) | PASS | PASS | PASS | **PASS** | `0` |

A transition from SKIP → PASS signals that the phase implementation is complete.
A FAIL in any previously-passing category signals a regression.

---

## 8. Debugging Tips

### Check which mechanisms are registered

```bash
./build/src/bin/util/softhsm2-util --show-slots --verbose
```

This lists all available slots and token info, but not mechanisms directly.
Use `pqc_validate --verbose` to see which mechanisms return
`CKR_MECHANISM_INVALID` vs. `CKR_OK`.

### CKR_MECHANISM_INVALID on a classical algorithm

Means the mechanism was not registered in `SoftHSM::prepareSupportedMechanisms()`.
Check `src/lib/SoftHSM.cpp` around that function and verify the
`CKM_*` constant is listed.

### Token not found / CKR_TOKEN_NOT_PRESENT

The token directory may be missing or pointing to the wrong path.
Check your `SOFTHSM2_CONF` environment variable:

```bash
echo $SOFTHSM2_CONF
./build/src/bin/util/softhsm2-util --show-slots
```

Re-initialize if needed (destructive — deletes existing tokens):

```bash
rm -rf /path/to/tokens/*
./build/src/bin/util/softhsm2-util \
    --init-token --slot 0 --label "pqctest" --so-pin 1234 --pin 5678
```

### ML-KEM SKIP — `C_EncapsulateKey not found`

`pqc_validate` loads `C_EncapsulateKey` and `C_DecapsulateKey` via `dlsym`.
If the warning appears, the symbols are not exported from the library:

```bash
# Check exported symbols
nm -gD build/src/lib/libsofthsmv3.dylib | grep -i encapsulate
```

If the function is absent, Phase 3 (ML-KEM) is not yet implemented.

### Shared secret mismatch in ECDH / ML-KEM

This usually means the EC point format is wrapped in a DER OCTET STRING.
The `pqc_validate` `stripEcPointWrapper()` helper handles this
automatically, but if you see `CKR_ARGUMENTS_BAD` from `C_DeriveKey`,
inspect the raw `CKA_EC_POINT` byte content:

```bash
./pqc_validate ./build/src/lib/libsofthsmv3.dylib --verbose 2>&1 | grep -A5 "ECDH"
```

### OpenSSL version mismatch

```bash
# Verify the library was linked against the expected OpenSSL
otool -L build/src/lib/libsofthsmv3.dylib | grep ssl   # macOS
ldd build/src/lib/libsofthsmv3.so | grep ssl           # Linux
```

### Enable debug logging

Set the log level in your `softhsmv3.conf`:

```ini
log.level = DEBUG
```

Or at CMake configure time:

```bash
cmake -B build -DDEFAULT_LOG_LEVEL=DEBUG ...
```

---

## 9. CI Integration

### Minimal CI snippet (GitHub Actions)

```yaml
- name: Install dependencies
  run: |
    sudo apt-get install -y cmake libssl-dev libcppunit-dev

- name: Build
  run: |
    cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
    cmake --build build -j$(nproc)

- name: Run CppUnit tests
  run: cd build && make check

- name: Download json.hpp
  run: |
    curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
         -o tests/json.hpp

- name: Build pqc_validate
  run: |
    g++ -o pqc_validate tests/pqc_validate.cpp \
        -ldl -std=c++17 -I src/lib/pkcs11 -I tests/

- name: Run pqc_validate
  run: |
    ./build/src/bin/util/softhsm2-util \
        --init-token --slot 0 --label "pqctest" --so-pin 1234 --pin 5678
    ./pqc_validate ./build/src/lib/libsofthsmv3.so \
        --so-pin 1234 --user-pin 5678

- name: Upload result JSON
  uses: actions/upload-artifact@v4
  with:
    name: pqc-validate-results
    path: pqc_validate_*.json
```

### Interpreting CI results

- Exit code `0` with all classical tests PASS and PQC tests SKIP → Phase 1 is clean.
- Any FAIL → regression; check the `error` field in the JSON artifact.
- Upload the JSON artifact to track SKIP→PASS transitions across phases.

---

## 10. Key Template Requirements

### Attribute check flags (P11Attribute.h)

| Flag | Value | Meaning |
| --- | --- | --- |
| `ck1` | 1 | MUST NOT be specified on `C_CreateObject` |
| `ck2` | 2 | MUST NOT be specified on `C_CopyObject` / key generation |
| `ck3` | 4 | MUST be specified when created via `C_GenerateKey` / `C_GenerateKeyPair` |
| `ck4` | 8 | Set internally after creation; caller must not supply |
| `ck6` | 32 | MUST NOT be specified on `C_UnwrapKey` |

`CreateObject` with `OBJECT_OP_GENERATE` enforces **ck3**: if the attribute is not in the
caller's template, it returns `CKR_TEMPLATE_INCOMPLETE`.

Source: `src/lib/P11Objects.cpp` lines 261–282, `src/lib/P11Attributes.h` lines 76–80.

---

### C_EncapsulateKey / C_DecapsulateKey — output secret key template

Source: `src/lib/SoftHSM_kem.cpp` lines 221–268 (encapsulate) / 395–443 (decapsulate).

**Default values applied before caller template is merged (bImplicit = true):**

| Attribute | Default | Notes |
| --- | --- | --- |
| `CKA_CLASS` | `CKO_SECRET_KEY` | Hardcoded in secretAttribs; must equal `CKO_SECRET_KEY` if supplied |
| `CKA_TOKEN` | `CK_FALSE` | Session object (not persisted to disk) |
| `CKA_PRIVATE` | `CK_TRUE` | Value is encrypted-at-rest in the token |
| `CKA_KEY_TYPE` | `CKK_GENERIC_SECRET` | Hardcoded; caller override stripped |

**Attributes the implementation strips from the caller template (never forwarded to CreateObject):**
`CKA_CLASS`, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_KEY_TYPE`, `CKA_VALUE`

**Mandatory caller attribute — `CKA_VALUE_LEN` (0x00000161):**

`P11AttrValueLen` is registered with `ck2|ck3` for `P11GenericSecretKeyObj`
(`P11Objects.cpp` line 1472). Because `CreateObject` is called with `OBJECT_OP_GENERATE`,
the `ck3` check fires and returns `CKR_TEMPLATE_INCOMPLETE` if `CKA_VALUE_LEN` is absent.

For ML-KEM, the shared secret is **always 32 bytes** for all parameter sets
(ML-KEM-512, -768, -1024) per FIPS 203 §7. Always supply:

```c
CK_ULONG valueLen = 32;
CK_ATTRIBUTE tpl[] = {
    { CKA_CLASS,     &secretClass, sizeof(secretClass) },
    { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
    { CKA_SENSITIVE,   &bFalse,   sizeof(bFalse)       },  // optional
    { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue)         },  // optional
};
C_EncapsulateKey(hSession, &mech, hPubKey, tpl, 4, pCiphertext, &ctLen, &hSecret);
```

Omitting `CKA_VALUE_LEN` → `CKR_TEMPLATE_INCOMPLETE (0x000000d0)`.

**Attributes written internally (do NOT include in template):**

| Attribute | Flag | Written by |
| --- | --- | --- |
| `CKA_VALUE` | ck4 | Injected post-`CreateObject` with actual shared secret bytes |
| `CKA_LOCAL` | ck4 | Set to `false` (key imported from external operation) |
| `CKA_ALWAYS_SENSITIVE` | ck4 | Set to `false` |
| `CKA_NEVER_EXTRACTABLE` | ck4 | Set to `false` |

---

### C_GenerateKeyPair — ML-KEM / ML-DSA public and private key templates

Source: `src/lib/SoftHSM_kem.cpp` lines 50–100, `src/lib/SoftHSM_sign.cpp`.

Both `CKA_PARAMETER_SET` (0x0000061d) and the class/key-type must be in the template.
For the public key: `CKA_ENCAPSULATE = CK_TRUE` (0x00000633) is required by ML-KEM;
for the private key: `CKA_DECAPSULATE = CK_TRUE` (0x00000634).

Minimal working templates:

```c
// Public key
CK_ATTRIBUTE pubTpl[] = {
    { CKA_CLASS,         &pubClass,    sizeof(pubClass)    },
    { CKA_KEY_TYPE,      &kkMlKem,     sizeof(kkMlKem)     },
    { CKA_PARAMETER_SET, &paramSet512, sizeof(paramSet512) }, // CKP_ML_KEM_512/768/1024
    { CKA_ENCAPSULATE,   &bTrue,       sizeof(bTrue)       },
};
// Private key
CK_ATTRIBUTE privTpl[] = {
    { CKA_CLASS,         &privClass,   sizeof(privClass)   },
    { CKA_KEY_TYPE,      &kkMlKem,     sizeof(kkMlKem)     },
    { CKA_PARAMETER_SET, &paramSet512, sizeof(paramSet512) },
    { CKA_DECAPSULATE,   &bTrue,       sizeof(bTrue)       },
    { CKA_SENSITIVE,     &bTrue,       sizeof(bTrue)       },
    { CKA_EXTRACTABLE,   &bFalse,      sizeof(bFalse)      },
};
```

---

## Related Files

| File | Description |
|---|---|
| `tests/pqc_validate.cpp` | Standalone validation program |
| `tests/pqc_validate_ops.json` | Operations template (70 test cases) |
| `tests/README.md` | Build + run quick-reference |
| `src/lib/test/` | CppUnit p11test suite |
| `src/lib/pkcs11/pkcs11t.h` | All `CKM_*`, `CKK_*`, `CKA_*`, `CKP_*` constants |
| `src/lib/pkcs11/pkcs11f.h` | `C_EncapsulateKey` / `C_DecapsulateKey` signatures |
| `docs/gap-analysis-pkcs11-v3.2.md` | PKCS#11 v3.2 gap analysis |
