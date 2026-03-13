#![allow(clippy::missing_safety_doc)]
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use wasm_bindgen::prelude::*;

use crate::constants::*;
use crate::state::*;


/// Monotonically increasing session handle counter (PKCS#11 requires unique handles).
pub static NEXT_SESSION_HANDLE: AtomicU32 = AtomicU32::new(1);

// Install panic hook on WASM start — turns panics into console.error with stack traces
#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}

// Algorithm family identifiers (stored in CKA_PRIV_ALGO_FAMILY)
pub const ALGO_ML_KEM: u32 = 1;
pub const ALGO_ML_DSA: u32 = 2;
pub const ALGO_SLH_DSA: u32 = 3;
pub const ALGO_RSA: u32 = 4;
pub const ALGO_ECDSA: u32 = 5;
pub const ALGO_EDDSA: u32 = 6;
pub const ALGO_ECDH_P256: u32 = 7;
pub const ALGO_ECDH_X25519: u32 = 8;

// ECDSA curve identifiers (stored in CKA_PRIV_PARAM_SET)
pub const CURVE_P256: u32 = 256;
pub const CURVE_P384: u32 = 384;

// ── Object Store ─────────────────────────────────────────────────────────────

pub type Attributes = HashMap<u32, Vec<u8>>;

pub(crate) enum DigestCtx {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha3_256(sha3::Sha3_256),
    Sha3_512(sha3::Sha3_512),
}

pub struct FindCtx {
    pub handles: Vec<u32>,
    pub cursor: usize,
}

// ── Template Parsing ─────────────────────────────────────────────────────────

/// Read a CK_ULONG attribute from a CK_ATTRIBUTE template array.
/// Each CK_ATTRIBUTE is 12 bytes: type(4) + pValue(4) + ulValueLen(4).
pub unsafe fn get_attr_ulong(template: *mut u8, count: u32, attr_type: u32) -> Option<u32> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u32;
            if !val_ptr.is_null() {
                return Some(*val_ptr);
            }
        }
    }
    None
}

/// Read a byte-array attribute from a CK_ATTRIBUTE template array.
pub unsafe fn get_attr_bytes(template: *mut u8, count: u32, attr_type: u32) -> Option<Vec<u8>> {
    if template.is_null() {
        return None;
    }
    if count > 65536 {
        return None; // Guard against malformed templates with huge count values
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let t = *ptr.add((i * 3) as usize);
        if t == attr_type {
            let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
            if !val_ptr.is_null() && val_len > 0 {
                return Some(std::slice::from_raw_parts(val_ptr, val_len).to_vec());
            }
        }
    }
    None
}

/// Copy all attributes from a caller's CK_ATTRIBUTE template into the attrs map.
/// Skips: CKA_VALUE (key material) and internal CKA_PRIV_* (>= 0xFFFF0000).
/// Call AFTER setting defaults so the caller's template can override them.
pub unsafe fn absorb_template_attrs(attrs: &mut Attributes, template: *mut u8, count: u32) {
    if template.is_null() || count == 0 || count > 65536 {
        return;
    }
    let ptr = template as *mut u32;
    for i in 0..count {
        let attr_type = *ptr.add((i * 3) as usize);
        let val_ptr = *ptr.add((i * 3 + 1) as usize) as usize as *const u8;
        let val_len = *ptr.add((i * 3 + 2) as usize) as usize;
        // Skip key material and internal private attrs
        if attr_type == CKA_VALUE || attr_type >= 0xFFFF0000 {
            continue;
        }
        if !val_ptr.is_null() && val_len > 0 {
            let v = std::slice::from_raw_parts(val_ptr, val_len).to_vec();
            attrs.insert(attr_type, v);
        }
    }
}

// ── Session/Token Info ───────────────────────────────────────────────────────

pub unsafe fn write_fixed_str(buf: *mut u8, offset: usize, s: &str, max_len: usize) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(max_len);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(offset), copy_len);
}

// ── SLH-DSA Macros ──────────────────────────────────────────────────────────

#[macro_export]
macro_rules! slh_dsa_keygen {
    ($ps:ty, $n:expr, $pub_attrs:expr, $prv_attrs:expr) => {{
        let n: usize = $n;
        let mut seed = [0u8; 96]; // max: 32 * 3 for 256-bit
        if getrandom::getrandom(&mut seed[..n * 3]).is_err() {
            return CKR_FUNCTION_FAILED;
        }
        let sk = slh_dsa::SigningKey::<$ps>::slh_keygen_internal(
            &seed[..n],
            &seed[n..2 * n],
            &seed[2 * n..3 * n],
        );
        use signature::Keypair;
        let vk = sk.verifying_key();
        $pub_attrs.insert(CKA_VALUE, vk.to_vec());
        $prv_attrs.insert(CKA_VALUE, sk.to_vec());
        seed.zeroize();
    }};
}

#[macro_export]
macro_rules! slh_dsa_sign {
    ($ps:ty, $sk_bytes:expr, $msg:expr) => {{
        let sk = slh_dsa::SigningKey::<$ps>::try_from($sk_bytes)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig = sk
            .try_sign_with_context($msg, &[], None)
            .map_err(|_| CKR_FUNCTION_FAILED)?;
        Ok(sig.to_vec())
    }};
}

#[macro_export]
macro_rules! slh_dsa_verify {
    ($ps:ty, $pk_bytes:expr, $msg:expr, $sig_bytes:expr) => {{
        let vk = slh_dsa::VerifyingKey::<$ps>::try_from($pk_bytes)
            .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        let sig =
            slh_dsa::Signature::<$ps>::try_from($sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
        vk.try_verify_with_context($msg, &[], &sig)
            .map_err(|_| CKR_SIGNATURE_INVALID)
    }};
}

// ── SubjectPublicKeyInfo (SPKI) DER Builders ─────────────────────────────────
//
// These functions construct DER-encoded SubjectPublicKeyInfo (RFC 5480 / RFC 8410)
// from raw public key bytes. Headers are constant for each curve.

/// Build SPKI DER for P-256 (secp256r1) from a 65-byte uncompressed point.
/// Structure: SEQUENCE { AlgorithmIdentifier { ecPublicKey, secp256r1 }, BIT STRING { 00 || pt } }
pub fn build_ec_spki_p256(pt: &[u8]) -> Vec<u8> {
    // AlgId for P-256: 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107
    // BIT STRING header: 03 <len+1> 00
    let alg_id: &[u8] = &[
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // secp256r1 OID
    ];
    build_spki_from_parts(alg_id, pt)
}

/// Build SPKI DER for P-384 (secp384r1) from a 97-byte uncompressed point.
pub fn build_ec_spki_p384(pt: &[u8]) -> Vec<u8> {
    // AlgId for P-384: 30 10 06 07 2a8648ce3d0201 06 05 2b8104 0022
    let alg_id: &[u8] = &[
        0x30, 0x10,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,               // secp384r1 OID
    ];
    build_spki_from_parts(alg_id, pt)
}

/// Build SPKI DER for Ed25519 (id-EdDSA, OID 1.3.101.112) from a 32-byte key.
pub fn build_ed25519_spki(pk: &[u8]) -> Vec<u8> {
    // AlgId: 30 05 06 03 2b6570
    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    build_spki_from_parts(alg_id, pk)
}

/// Assemble SEQUENCE { alg_id_der | BIT STRING { 00 || key_bytes } }.
pub fn build_spki_from_parts(alg_id: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    // BIT STRING: tag 03 | len (key_bytes.len + 1 for unused-bits byte 00) | 00 | key_bytes
    let bs_len = key_bytes.len() + 1;
    let bs_len_enc = der_length(bs_len);
    let inner_len = alg_id.len() + 1 + bs_len_enc.len() + bs_len;
    let outer_len_enc = der_length(inner_len);

    let mut out = Vec::with_capacity(1 + outer_len_enc.len() + inner_len);
    out.push(0x30); // SEQUENCE tag
    out.extend_from_slice(&outer_len_enc);
    out.extend_from_slice(alg_id);
    out.push(0x03); // BIT STRING tag
    out.extend_from_slice(&bs_len_enc);
    out.push(0x00); // unused bits = 0
    out.extend_from_slice(key_bytes);
    out
}

/// Encode a DER length field (short or long form).
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

// ── Pre-Hash Dispatch Helpers ────────────────────────────────────────────────

/// Returns true if `mech` is one of the CKM_HASH_ML_DSA_* pre-hash variants.
pub fn is_prehash_ml_dsa(mech: u32) -> bool {
    matches!(
        mech,
        CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512
            | CKM_HASH_ML_DSA_SHAKE128
            | CKM_HASH_ML_DSA_SHAKE256
    )
}

/// Returns true if `mech` is one of the CKM_HASH_SLH_DSA_* pre-hash variants.
pub fn is_prehash_slh_dsa(mech: u32) -> bool {
    matches!(
        mech,
        CKM_HASH_SLH_DSA_SHA224
            | CKM_HASH_SLH_DSA_SHA256
            | CKM_HASH_SLH_DSA_SHA384
            | CKM_HASH_SLH_DSA_SHA512
            | CKM_HASH_SLH_DSA_SHA3_224
            | CKM_HASH_SLH_DSA_SHA3_256
            | CKM_HASH_SLH_DSA_SHA3_384
            | CKM_HASH_SLH_DSA_SHA3_512
            | CKM_HASH_SLH_DSA_SHAKE128
            | CKM_HASH_SLH_DSA_SHAKE256
    )
}

/// Hash `msg` with the hash function encoded in `mech`.
/// Used by CKM_HASH_ML_DSA_* and CKM_HASH_SLH_DSA_* to compute the pre-hash before signing.
pub fn prehash_message(mech: u32, msg: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest as Sha2Digest;
    match mech {
        CKM_HASH_ML_DSA_SHA224 | CKM_HASH_SLH_DSA_SHA224 => {
            Some(sha2::Sha224::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA256 | CKM_HASH_SLH_DSA_SHA256 => {
            Some(sha2::Sha256::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA384 | CKM_HASH_SLH_DSA_SHA384 => {
            Some(sha2::Sha384::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA512 | CKM_HASH_SLH_DSA_SHA512 => {
            Some(sha2::Sha512::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_224 | CKM_HASH_SLH_DSA_SHA3_224 => {
            Some(sha3::Sha3_224::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_256 | CKM_HASH_SLH_DSA_SHA3_256 => {
            Some(sha3::Sha3_256::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_384 | CKM_HASH_SLH_DSA_SHA3_384 => {
            Some(sha3::Sha3_384::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHA3_512 | CKM_HASH_SLH_DSA_SHA3_512 => {
            Some(sha3::Sha3_512::digest(msg).to_vec())
        }
        CKM_HASH_ML_DSA_SHAKE128 | CKM_HASH_SLH_DSA_SHAKE128 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake128::default();
            h.update(msg);
            let mut out = vec![0u8; 32];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        CKM_HASH_ML_DSA_SHAKE256 | CKM_HASH_SLH_DSA_SHAKE256 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            h.update(msg);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            Some(out)
        }
        _ => None,
    }
}

// ── Sign Helpers ────────────────────────────────────────────────────────────

pub fn sign_ml_dsa(ps: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use signature::Signer;
    match ps {
        CKP_ML_DSA_44 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_expanded(&sk_enc);
            Ok(sk
                .try_sign(msg)
                .map_err(|_| CKR_FUNCTION_FAILED)?
                .encode()
                .as_slice()
                .to_vec())
        }
        CKP_ML_DSA_65 | 0 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_expanded(&sk_enc);
            Ok(sk
                .try_sign(msg)
                .map_err(|_| CKR_FUNCTION_FAILED)?
                .encode()
                .as_slice()
                .to_vec())
        }
        CKP_ML_DSA_87 => {
            let sk_enc = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::try_from(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            #[allow(deprecated)]
            let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_expanded(&sk_enc);
            Ok(sk
                .try_sign(msg)
                .map_err(|_| CKR_FUNCTION_FAILED)?
                .encode()
                .as_slice()
                .to_vec())
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn sign_slh_dsa(ps: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_sign!(slh_dsa::Sha2_128s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_sign!(slh_dsa::Shake128s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_sign!(slh_dsa::Sha2_128f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_sign!(slh_dsa::Shake128f, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_sign!(slh_dsa::Sha2_192s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_sign!(slh_dsa::Shake192s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_sign!(slh_dsa::Sha2_192f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_sign!(slh_dsa::Shake192f, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_sign!(slh_dsa::Sha2_256s, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_sign!(slh_dsa::Shake256s, sk_bytes, msg),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_sign!(slh_dsa::Sha2_256f, sk_bytes, msg),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_sign!(slh_dsa::Shake256f, sk_bytes, msg),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn sign_hmac(mech: u32, key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use hmac::{Hmac, Mac};
    match mech {
        CKM_SHA256_HMAC => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA384_HMAC => {
            let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA512_HMAC => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_256_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_256>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CKM_SHA3_512_HMAC => {
            let mut mac = Hmac::<sha3::Sha3_512>::new_from_slice(key_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            mac.update(msg);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_kmac(mech: u32, key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use sp800_185::KMac;
    match mech {
        CKM_KMAC_128 => {
            let mut mac = KMac::new_kmac128(key_bytes, b"");
            mac.update(msg);
            let mut out = vec![0u8; 32];
            mac.finalize(&mut out);
            Ok(out)
        }
        CKM_KMAC_256 => {
            let mut mac = KMac::new_kmac256(key_bytes, b"");
            mac.update(msg);
            let mut out = vec![0u8; 64];
            mac.finalize(&mut out);
            Ok(out)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn sign_rsa(mech: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignatureEncoding;
    let private_key =
        rsa::RsaPrivateKey::from_pkcs8_der(sk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    match mech {
        CKM_SHA256_RSA_PKCS => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::Signer;
            let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
            let sig = signing_key.sign(msg);
            Ok(sig.to_vec())
        }
        CKM_SHA256_RSA_PKCS_PSS => {
            use rsa::pss::BlindedSigningKey;
            use rsa::signature::RandomizedSigner;
            let signing_key = BlindedSigningKey::<sha2::Sha256>::new(private_key);
            let mut rng = rand::rngs::OsRng;
            let sig = signing_key
                .try_sign_with_rng(&mut rng, msg)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_ecdsa(mech: u32, curve: u32, sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            use p256::ecdsa::signature::Signer;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        (CKM_ECDSA_SHA384, CURVE_P384) => {
            use p384::ecdsa::signature::Signer;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig: p384::ecdsa::Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-3 prehash variants on P-256 — manually hash then sign prehash bytes
        (CKM_ECDSA_SHA3_224, CURVE_P256)
        | (CKM_ECDSA_SHA3_224, 0)
        | (CKM_ECDSA_SHA3_256, CURVE_P256)
        | (CKM_ECDSA_SHA3_256, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha3::Digest as _;
            let sk = p256::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_224 => sha3::Sha3_224::digest(msg).to_vec(),
                _ => sha3::Sha3_256::digest(msg).to_vec(),
            };
            let sig: p256::ecdsa::Signature =
                sk.sign_prehash(&hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        // SHA-3 prehash variants on P-384 — manually hash then sign prehash bytes
        (CKM_ECDSA_SHA3_384, CURVE_P384) | (CKM_ECDSA_SHA3_512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashSigner;
            use sha3::Digest as _;
            let sk = p384::ecdsa::SigningKey::from_slice(sk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_512 => sha3::Sha3_512::digest(msg).to_vec(),
                _ => sha3::Sha3_384::digest(msg).to_vec(),
            };
            let sig: p384::ecdsa::Signature =
                sk.sign_prehash(&hash).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn sign_eddsa(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    if sk_bytes.len() != 32 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    use ed25519_dalek::Signer;
    Ok(sk.sign(msg).to_bytes().to_vec())
}

pub fn sign_eddsa_ph(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use sha2::Digest;
    if sk_bytes.len() != 32 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let prehash = sha2::Sha512::new().chain_update(msg);
    sk.sign_prehashed(prehash, None)
        .map(|sig| sig.to_bytes().to_vec())
        .map_err(|_| CKR_FUNCTION_FAILED)
}

pub fn get_sig_len(mech: u32, hkey: u32) -> u32 {
    let ps = get_object_param_set(hkey);
    match mech {
        CKM_ML_DSA => match ps {
            CKP_ML_DSA_44 => 2420,
            CKP_ML_DSA_87 => 4627,
            _ => 3309,
        },
        // Pre-hash ML-DSA variants produce the same signature length as pure ML-DSA
        m if is_prehash_ml_dsa(m) => match ps {
            CKP_ML_DSA_44 => 2420,
            CKP_ML_DSA_87 => 4627,
            _ => 3309,
        },
        CKM_SLH_DSA => match ps {
            CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHAKE_128S => 7856,
            CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128F => 17088,
            CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHAKE_192S => 16224,
            CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192F => 35664,
            CKP_SLH_DSA_SHA2_256S | CKP_SLH_DSA_SHAKE_256S => 29792,
            _ => 49856,
        },
        // Pre-hash SLH-DSA variants produce the same signature length as pure SLH-DSA
        m if is_prehash_slh_dsa(m) => match ps {
            CKP_SLH_DSA_SHA2_128S | CKP_SLH_DSA_SHAKE_128S => 7856,
            CKP_SLH_DSA_SHA2_128F | CKP_SLH_DSA_SHAKE_128F => 17088,
            CKP_SLH_DSA_SHA2_192S | CKP_SLH_DSA_SHAKE_192S => 16224,
            CKP_SLH_DSA_SHA2_192F | CKP_SLH_DSA_SHAKE_192F => 35664,
            CKP_SLH_DSA_SHA2_256S | CKP_SLH_DSA_SHAKE_256S => 29792,
            _ => 49856,
        },
        CKM_SHA256_HMAC | CKM_SHA3_256_HMAC => 32,
        CKM_SHA384_HMAC => 48,
        CKM_SHA512_HMAC | CKM_SHA3_512_HMAC => 64,
        CKM_KMAC_128 => 32,
        CKM_KMAC_256 => 64,
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => 512,
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 => 64,
        CKM_ECDSA_SHA384 | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => 96,
        CKM_EDDSA | CKM_EDDSA_PH => 64,
        _ => 512,
    }
}

// ── Verify Helpers ──────────────────────────────────────────────────────────

pub fn verify_ml_dsa(ps: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use signature::Verifier;
    match ps {
        CKP_ML_DSA_44 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(sig_bytes)
                .map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKP_ML_DSA_65 | 0 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes)
                .map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKP_ML_DSA_87 => {
            let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&pk_enc);
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(sig_bytes)
                .map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn verify_slh_dsa(ps: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    match ps {
        CKP_SLH_DSA_SHA2_128S => slh_dsa_verify!(slh_dsa::Sha2_128s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128S => slh_dsa_verify!(slh_dsa::Shake128s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_128F => slh_dsa_verify!(slh_dsa::Sha2_128f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_128F => slh_dsa_verify!(slh_dsa::Shake128f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192S => slh_dsa_verify!(slh_dsa::Sha2_192s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192S => slh_dsa_verify!(slh_dsa::Shake192s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_192F => slh_dsa_verify!(slh_dsa::Sha2_192f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_192F => slh_dsa_verify!(slh_dsa::Shake192f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256S => slh_dsa_verify!(slh_dsa::Sha2_256s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256S => slh_dsa_verify!(slh_dsa::Shake256s, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHA2_256F => slh_dsa_verify!(slh_dsa::Sha2_256f, pk_bytes, msg, sig_bytes),
        CKP_SLH_DSA_SHAKE_256F => slh_dsa_verify!(slh_dsa::Shake256f, pk_bytes, msg, sig_bytes),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

pub fn verify_hmac(mech: u32, key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    let expected = sign_hmac(mech, key_bytes, msg)?;
    if expected.len() == sig_bytes.len() && expected == sig_bytes {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID)
    }
}

pub fn verify_rsa(mech: u32, pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use rsa::signature::Verifier;
    if pk_bytes.len() < 8 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let n_len = u32::from_le_bytes([pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]]) as usize;
    if pk_bytes.len() < 4 + n_len + 1 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let n = rsa::BigUint::from_bytes_be(&pk_bytes[4..4 + n_len]);
    let e = rsa::BigUint::from_bytes_be(&pk_bytes[4 + n_len..]);
    let public_key = rsa::RsaPublicKey::new(n, e).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;

    match mech {
        CKM_SHA256_RSA_PKCS => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key);
            let sig =
                rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        CKM_SHA256_RSA_PKCS_PSS => {
            let vk = rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key);
            let sig =
                rsa::pss::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn verify_ecdsa(
    mech: u32,
    curve: u32,
    pk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), u32> {
    match (mech, curve) {
        (CKM_ECDSA_SHA256, CURVE_P256) | (CKM_ECDSA_SHA256, 0) => {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        (CKM_ECDSA_SHA384, CURVE_P384) => {
            use p384::ecdsa::signature::Verifier;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-3 prehash variants on P-256 — manually hash then verify prehash bytes
        (CKM_ECDSA_SHA3_224, CURVE_P256)
        | (CKM_ECDSA_SHA3_224, 0)
        | (CKM_ECDSA_SHA3_256, CURVE_P256)
        | (CKM_ECDSA_SHA3_256, 0) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use sha3::Digest as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p256::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_224 => sha3::Sha3_224::digest(msg).to_vec(),
                _ => sha3::Sha3_256::digest(msg).to_vec(),
            };
            vk.verify_prehash(&hash, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        // SHA-3 prehash variants on P-384 — manually hash then verify prehash bytes
        (CKM_ECDSA_SHA3_384, CURVE_P384) | (CKM_ECDSA_SHA3_512, CURVE_P384) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use sha3::Digest as _;
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let sig =
                p384::ecdsa::Signature::try_from(sig_bytes).map_err(|_| CKR_SIGNATURE_INVALID)?;
            let hash: Vec<u8> = match mech {
                CKM_ECDSA_SHA3_512 => sha3::Sha3_512::digest(msg).to_vec(),
                _ => sha3::Sha3_384::digest(msg).to_vec(),
            };
            vk.verify_prehash(&hash, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub fn verify_eddsa(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.try_into().unwrap())
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().unwrap());
    use ed25519_dalek::Verifier;
    vk.verify(msg, &sig).map_err(|_| CKR_SIGNATURE_INVALID)
}

pub fn verify_eddsa_ph(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), u32> {
    use sha2::Digest;
    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.try_into().unwrap())
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().unwrap());
    let prehash = sha2::Sha512::new().chain_update(msg);
    vk.verify_prehashed(prehash, None, &sig)
        .map_err(|_| CKR_SIGNATURE_INVALID)
}
