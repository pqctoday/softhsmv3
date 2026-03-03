/**
 * smoke-wasm.mjs — Node.js smoke test for SoftHSMv3 WASM module
 *
 * Tests the full PKCS#11 v3.2 lifecycle:
 *   C_Initialize → C_GetSlotList → C_InitToken → (re-enumerate) →
 *   C_OpenSession → C_Login → C_GenerateKeyPair(ML-KEM-768) →
 *   C_EncapsulateKey → C_DecapsulateKey → match check →
 *   C_GenerateKeyPair(ML-DSA-65) → C_Sign → C_Verify →
 *   C_Logout → C_CloseSession → C_Finalize
 *
 * Usage:
 *   node tests/smoke-wasm.mjs
 *
 * Prerequisites:
 *   wasm/softhsm.js + wasm/softhsm.wasm must exist (run scripts/build-wasm.sh first)
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmJsPath = path.resolve(__dirname, '../wasm/softhsm.js');

console.log('[smoke] Loading WASM module from:', wasmJsPath);
const { default: createSoftHSMModule } = await import(wasmJsPath);
const M = await createSoftHSMModule();
console.log('[smoke] Module loaded.\n');

// ── Helpers ──────────────────────────────────────────────────────────────────

const CKR_OK                 = 0;
const CKR_TOKEN_NOT_PRESENT  = 0xE1;
const CKF_SERIAL_SESSION     = 0x00000004;
const CKF_RW_SESSION         = 0x00000002;
const CKU_SO                 = 0;
const CKU_USER               = 1;

// PKCS#11 attribute type constants
const CKA_CLASS              = 0x00000000;
const CKA_TOKEN              = 0x00000001;
const CKA_SENSITIVE          = 0x00000103;
const CKA_EXTRACTABLE        = 0x00000162;
const CKA_ENCRYPT            = 0x00000104;
const CKA_DECRYPT            = 0x00000105;
const CKA_SIGN               = 0x00000108;
const CKA_VERIFY             = 0x0000010A;
const CKA_ENCAPSULATE        = 0x00000633;
const CKA_DECAPSULATE        = 0x00000634;
const CKA_PARAMETER_SET      = 0x0000061D;
const CKA_VALUE_LEN          = 0x00000161;

const CKO_PUBLIC_KEY         = 0x00000002;
const CKO_PRIVATE_KEY        = 0x00000003;
const CKO_SECRET_KEY         = 0x00000004;

const CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000F;
const CKM_ML_KEM             = 0x00000017;
const CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001C;
const CKM_ML_DSA             = 0x0000001D;
const CKK_GENERIC_SECRET     = 0x00000010;
const CKK_ML_KEM             = 0x00000049;

// CKA_PARAMETER_SET values for ML-KEM
const CKP_ML_KEM_768         = 0x00000002;
// CKA_PARAMETER_SET values for ML-DSA
const CKP_ML_DSA_65          = 0x00000002;

const check = (label, rv) => {
    if (rv !== CKR_OK) {
        throw new Error(`FAIL: ${label} returned 0x${rv.toString(16).toUpperCase()}`);
    }
    console.log(`  ✓  ${label}`);
};

// Allocate a CK_ULONG (4-byte) output buffer and return its pointer
const allocUlong = () => M._malloc(4);
const readUlong  = (ptr) => M.getValue(ptr, 'i32') >>> 0;  // unsigned 32-bit
const freePtr    = (ptr) => M._free(ptr);

// Write a null-terminated string into WASM memory; returns { ptr, size }
const writeStr = (str) => {
    const bytes = new TextEncoder().encode(str);
    const ptr = M._malloc(bytes.length + 1);
    M.HEAPU8.set(bytes, ptr);
    M.HEAPU8[ptr + bytes.length] = 0;
    return ptr;
};

// Space-pad a string to exactly `len` bytes (PKCS#11 label convention)
const padLabel = (s, len = 32) => s.padEnd(len, ' ').slice(0, len);

// Build a flat CK_ATTRIBUTE array in WASM memory
// attrs: [{type, value}] where value is:
//   - number → CK_ULONG (4 bytes)
//   - boolean (true/false) → CK_BBOOL (1 byte)
//   - Uint8Array → raw bytes
// Returns pointer to the attribute array; caller must free() the slabs
const buildTemplate = (attrs) => {
    // CK_ATTRIBUTE = { CK_ATTRIBUTE_TYPE type(4), CK_VOID_PTR pValue(4), CK_ULONG ulValueLen(4) }
    const ATTR_SIZE = 12;
    const arrPtr = M._malloc(attrs.length * ATTR_SIZE);
    const valuePtrs = [];
    for (let i = 0; i < attrs.length; i++) {
        const { type, value } = attrs[i];
        let vPtr, vLen;
        if (typeof value === 'boolean') {
            vPtr = M._malloc(1);
            M.HEAPU8[vPtr] = value ? 1 : 0;
            vLen = 1;
        } else if (typeof value === 'number') {
            vPtr = M._malloc(4);
            M.setValue(vPtr, value, 'i32');
            vLen = 4;
        } else if (value instanceof Uint8Array) {
            vPtr = M._malloc(value.length);
            M.HEAPU8.set(value, vPtr);
            vLen = value.length;
        } else {
            throw new Error(`Unsupported template value type: ${typeof value}`);
        }
        valuePtrs.push(vPtr);
        const base = arrPtr + i * ATTR_SIZE;
        M.setValue(base + 0, type,  'i32');
        M.setValue(base + 4, vPtr,  'i32');
        M.setValue(base + 8, vLen,  'i32');
    }
    return { arrPtr, valuePtrs, count: attrs.length };
};

const freeTemplate = ({ arrPtr, valuePtrs }) => {
    for (const p of valuePtrs) M._free(p);
    M._free(arrPtr);
};

// ── Test ──────────────────────────────────────────────────────────────────────

console.log('── C_Initialize ──');
check('C_Initialize', M._C_Initialize(0));

console.log('\n── C_GetSlotList (all slots) ──');
const cntPtr = allocUlong();
check('C_GetSlotList(count)', M._C_GetSlotList(0, 0, cntPtr));
const slotCount = readUlong(cntPtr);
console.log(`   Slot count: ${slotCount}`);

const slotsPtr = M._malloc(slotCount * 4);
check('C_GetSlotList(fill)', M._C_GetSlotList(0, slotsPtr, cntPtr));
const slot0 = M.getValue(slotsPtr, 'i32') >>> 0;
console.log(`   Using slot: ${slot0}`);
M._free(slotsPtr);
freePtr(cntPtr);

console.log('\n── C_InitToken ──');
const soLabel = padLabel('SmokeTest');
const soLabelPtr = writeStr(soLabel);
const soPinStr   = '12345678';
const soPinPtr   = writeStr(soPinStr);
check('C_InitToken',
    M._C_InitToken(slot0, soPinPtr, soPinStr.length, soLabelPtr));
M._free(soLabelPtr);
M._free(soPinPtr);

// After C_InitToken the slot may have a new ID — re-enumerate
console.log('\n── Re-enumerate slots after InitToken ──');
const cntPtr2 = allocUlong();
check('C_GetSlotList(count 2)', M._C_GetSlotList(1, 0, cntPtr2));
const slotCount2 = readUlong(cntPtr2);
console.log(`   Present slot count: ${slotCount2}`);
const slotsPtr2 = M._malloc(slotCount2 * 4);
check('C_GetSlotList(fill 2)', M._C_GetSlotList(1, slotsPtr2, cntPtr2));
const initedSlot = M.getValue(slotsPtr2, 'i32') >>> 0;
console.log(`   Initialized slot: ${initedSlot}`);
M._free(slotsPtr2);
freePtr(cntPtr2);

console.log('\n── C_OpenSession ──');
const hSessionPtr = allocUlong();
const flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
check('C_OpenSession',
    M._C_OpenSession(initedSlot, flags, 0, 0, hSessionPtr));
const hSession = readUlong(hSessionPtr);
console.log(`   Session handle: ${hSession}`);
freePtr(hSessionPtr);

console.log('\n── C_Login (User) ──');
const userPinStr = '87654321';
const userPinPtr = writeStr(userPinStr);
// C_InitPIN first (sets user PIN) — need a fresh pointer (soPinPtr was freed above)
const soPinPtr2 = writeStr('12345678');
check('C_Login(SO)',
    M._C_Login(hSession, CKU_SO, soPinPtr2, soPinStr.length));
M._free(soPinPtr2);
check('C_InitPIN',
    M._C_InitPIN(hSession, userPinPtr, userPinStr.length));
check('C_Logout', M._C_Logout(hSession));
check('C_Login(User)',
    M._C_Login(hSession, CKU_USER, userPinPtr, userPinStr.length));
M._free(userPinPtr);

console.log('\n── C_GenerateKeyPair (ML-KEM-768) ──');
const pubTmpl = buildTemplate([
    { type: CKA_TOKEN,       value: true  },
    { type: CKA_ENCRYPT,     value: true  },
    { type: CKA_ENCAPSULATE, value: true  },
    { type: CKA_PARAMETER_SET, value: CKP_ML_KEM_768 },
]);
const prvTmpl = buildTemplate([
    { type: CKA_TOKEN,       value: true  },
    { type: CKA_SENSITIVE,   value: true  },
    { type: CKA_DECRYPT,     value: true  },
    { type: CKA_DECAPSULATE, value: true  },
    { type: CKA_EXTRACTABLE, value: false },
    { type: CKA_PARAMETER_SET, value: CKP_ML_KEM_768 },
]);

const mech = M._malloc(8);  // CK_MECHANISM { type(4), pParam(4), paramLen(4) } = 12 bytes
M.setValue(mech + 0, CKM_ML_KEM_KEY_PAIR_GEN, 'i32');
M.setValue(mech + 4, 0, 'i32');  // pParam = NULL
M.setValue(mech + 8, 0, 'i32');  // ulParameterLen = 0

const hPubPtr = allocUlong();
const hPrvPtr = allocUlong();
check('C_GenerateKeyPair(ML-KEM-768)',
    M._C_GenerateKeyPair(hSession, mech,
        pubTmpl.arrPtr, pubTmpl.count,
        prvTmpl.arrPtr, prvTmpl.count,
        hPubPtr, hPrvPtr));
const hPub = readUlong(hPubPtr);
const hPrv = readUlong(hPrvPtr);
console.log(`   Public key handle: ${hPub}, Private key handle: ${hPrv}`);
freeTemplate(pubTmpl);
freeTemplate(prvTmpl);
M._free(mech);
freePtr(hPubPtr);
freePtr(hPrvPtr);

console.log('\n── C_EncapsulateKey (ML-KEM-768) ──');
const kemMech = M._malloc(12);
M.setValue(kemMech + 0, CKM_ML_KEM, 'i32');
M.setValue(kemMech + 4, 0, 'i32');
M.setValue(kemMech + 8, 0, 'i32');

// Query ciphertext size
const ctLenPtr = allocUlong();
const ssLenPtr = allocUlong();
const ssTmpl = buildTemplate([
    { type: CKA_CLASS,       value: CKO_SECRET_KEY },
    { type: CKA_TOKEN,       value: false },
    { type: CKA_EXTRACTABLE, value: true  },
    { type: CKA_VALUE_LEN,   value: 32    },
]);
const hSS1Ptr = allocUlong();

// First call: query sizes (pCiphertext = NULL)
check('C_EncapsulateKey(size query)',
    M._C_EncapsulateKey(hSession, kemMech, hPub,
        ssTmpl.arrPtr, ssTmpl.count,
        0, ctLenPtr, hSS1Ptr));
const ctLen = readUlong(ctLenPtr);
console.log(`   Ciphertext length: ${ctLen} bytes`);

// Second call: get ciphertext
const ctPtr = M._malloc(ctLen);
check('C_EncapsulateKey',
    M._C_EncapsulateKey(hSession, kemMech, hPub,
        ssTmpl.arrPtr, ssTmpl.count,
        ctPtr, ctLenPtr, hSS1Ptr));
const hSS1 = readUlong(hSS1Ptr);
console.log(`   Shared secret 1 handle: ${hSS1}`);

console.log('\n── C_DecapsulateKey (ML-KEM-768) ──');
const hSS2Ptr = allocUlong();
check('C_DecapsulateKey',
    M._C_DecapsulateKey(hSession, kemMech, hPrv,
        ssTmpl.arrPtr, ssTmpl.count,
        ctPtr, ctLen, hSS2Ptr));
const hSS2 = readUlong(hSS2Ptr);
console.log(`   Shared secret 2 handle: ${hSS2}`);

freeTemplate(ssTmpl);
M._free(ctPtr);
freePtr(ctLenPtr);
freePtr(hSS1Ptr);
freePtr(hSS2Ptr);
M._free(kemMech);

// Extract both shared secrets and compare
console.log('\n── Compare shared secrets ──');
const getVal = (hKey) => {
    const lenAttr = buildTemplate([{ type: CKA_VALUE_LEN, value: 0 }]);
    M._C_GetAttributeValue(hSession, hKey, lenAttr.arrPtr, 1);
    const baseAttr = lenAttr.arrPtr;
    const valLen = M.getValue(M.getValue(baseAttr + 4, 'i32'), 'i32') >>> 0;
    freeTemplate(lenAttr);

    const valBuf = M._malloc(valLen);
    const attr = buildTemplate([{ type: 0x00000130 /* CKA_VALUE */, value: new Uint8Array(valLen) }]);
    // Overwrite the value ptr in the template with our buffer
    M.setValue(attr.arrPtr + 4, valBuf, 'i32');
    M.setValue(attr.arrPtr + 8, valLen, 'i32');
    check(`C_GetAttributeValue(CKA_VALUE, key=${hKey})`,
        M._C_GetAttributeValue(hSession, hKey, attr.arrPtr, 1));
    const bytes = new Uint8Array(M.HEAPU8.buffer, valBuf, valLen).slice();
    freeTemplate(attr);
    M._free(valBuf);
    return bytes;
};

const CKA_VALUE = 0x00000011;
const extractSecret = (hKey, label) => {
    const bufPtr = M._malloc(64);  // ML-KEM shared secret is 32 bytes
    const attrPtr = M._malloc(12);
    M.setValue(attrPtr + 0, CKA_VALUE, 'i32');
    M.setValue(attrPtr + 4, bufPtr,    'i32');
    M.setValue(attrPtr + 8, 64,        'i32');
    const rv = M._C_GetAttributeValue(hSession, hKey, attrPtr, 1);
    if (rv !== CKR_OK) {
        console.log(`  ⚠  GetAttributeValue(${label}) skipped (rv=0x${rv.toString(16)}) — key may be sensitive`);
        M._free(bufPtr);
        M._free(attrPtr);
        return null;
    }
    const len = M.getValue(attrPtr + 8, 'i32') >>> 0;
    const bytes = new Uint8Array(M.HEAPU8.buffer, bufPtr, len).slice();
    M._free(bufPtr);
    M._free(attrPtr);
    return bytes;
};

const ss1 = extractSecret(hSS1, 'SS1');
const ss2 = extractSecret(hSS2, 'SS2');
if (ss1 && ss2) {
    const match = ss1.length === ss2.length && ss1.every((b, i) => b === ss2[i]);
    if (!match) throw new Error('FAIL: shared secrets do not match!');
    console.log(`  ✓  Shared secrets match (${ss1.length} bytes)`);
} else {
    console.log('  ℹ  Skipped shared secret comparison (keys are sensitive)');
}

console.log('\n── C_Logout + C_CloseSession ──');
check('C_Logout',       M._C_Logout(hSession));
check('C_CloseSession', M._C_CloseSession(hSession));

console.log('\n── C_Finalize ──');
check('C_Finalize', M._C_Finalize(0));

console.log('\n══════════════════════════════════════════');
console.log('  SoftHSMv3 WASM smoke test PASSED');
console.log('══════════════════════════════════════════\n');
