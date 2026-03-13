#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::constants::*;
use crate::crypto::*;
use crate::slh_dsa_keygen;
use crate::state::*;

// ── Session Management ───────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_Initialize)]
pub fn C_Initialize(_p_init_args: *mut u8) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Finalize)]
pub fn C_Finalize(_p_reserved: *mut u8) -> u32 {
    // Full reset: clear all objects, handles, and operation state
    OBJECTS.with(|o| o.borrow_mut().clear());
    NEXT_HANDLE.with(|h| *h.borrow_mut() = 100);
    SIGN_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_STATE.with(|s| s.borrow_mut().clear());
    ENCRYPT_STATE.with(|s| s.borrow_mut().clear());
    DECRYPT_STATE.with(|s| s.borrow_mut().clear());
    DIGEST_STATE.with(|s| s.borrow_mut().clear());
    FIND_STATE.with(|s| s.borrow_mut().clear());
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetSlotList)]
pub fn C_GetSlotList(_token_present: u8, p_slot_list: *mut u32, pul_count: *mut u32) -> u32 {
    unsafe {
        if p_slot_list.is_null() {
            *pul_count = 1;
        } else {
            *p_slot_list = 0;
            *pul_count = 1;
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_InitToken)]
pub fn C_InitToken(_slot_id: u32, _p_pin: *mut u8, _ul_pin_len: u32, _p_label: *mut u8) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_OpenSession)]
pub fn C_OpenSession(
    _slot_id: u32,
    _flags: u32,
    _p_application: *mut u8,
    _notify: *mut u8,
    ph_session: *mut u32,
) -> u32 {
    unsafe {
        *ph_session = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::Relaxed);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_CloseSession)]
pub fn C_CloseSession(h_session: u32) -> u32 {
    // Clean up all operation state for this session
    SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
    VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
    ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
    FIND_STATE.with(|s| s.borrow_mut().remove(&h_session));
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Login)]
pub fn C_Login(_h_session: u32, _user_type: u32, _p_pin: *mut u8, _ul_pin_len: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Logout)]
pub fn C_Logout(_h_session: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_InitPIN)]
pub fn C_InitPIN(_h_session: u32, _p_pin: *mut u8, _ul_pin_len: u32) -> u32 {
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetSessionInfo)]
pub fn C_GetSessionInfo(_h_session: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = 0;
        *ptr.add(1) = CKS_RW_USER_FUNCTIONS;
        *ptr.add(2) = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        *ptr.add(3) = 0;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetTokenInfo)]
pub fn C_GetTokenInfo(_slot_id: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        std::ptr::write_bytes(p_info, 0x20, 160);
        write_fixed_str(p_info, 0, "SoftHSM3-Rust", 32);
        write_fixed_str(p_info, 32, "PQC Today", 32);
        write_fixed_str(p_info, 64, "softhsmrustv3", 16);
        write_fixed_str(p_info, 80, "0001", 16);

        let ptr = p_info as *mut u32;
        *ptr.add(24) = 0x0004_040D;
        *ptr.add(25) = 256;
        *ptr.add(26) = 1;
        *ptr.add(27) = 256;
        *ptr.add(28) = 1;
        *ptr.add(29) = 256;
        *ptr.add(30) = 4;
        *p_info.add(140) = 3;
        *p_info.add(141) = 2;
        *p_info.add(142) = 0;
        *p_info.add(143) = 1;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetMechanismInfo)]
pub fn C_GetMechanismInfo(_slot_id: u32, mech_type: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (min_key, max_key, flags) = match mech_type {
        CKM_RSA_PKCS_KEY_PAIR_GEN => (2048, 4096, 0x00010000u32),
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => (2048, 4096, 0x00000800 | 0x00002000),
        CKM_RSA_PKCS_OAEP => (2048, 4096, 0x00000100 | 0x00000200),
        CKM_ML_KEM_KEY_PAIR_GEN => (512, 1024, 0x00010000),
        CKM_ML_KEM => (512, 1024, 0x10000000 | 0x20000000),
        CKM_ML_DSA_KEY_PAIR_GEN => (44, 87, 0x00010000),
        CKM_ML_DSA => (44, 87, 0x00000800 | 0x00002000),
        CKM_SLH_DSA_KEY_PAIR_GEN => (128, 256, 0x00010000),
        CKM_SLH_DSA => (128, 256, 0x00000800 | 0x00002000),
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_512 => (0, 0, 0x00000400),
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_512_HMAC => (16, 64, 0x00000800 | 0x00002000),
        CKM_KMAC_128 | CKM_KMAC_256 => (16, 64, 0x00000800 | 0x00002000),
        CKM_GENERIC_SECRET_KEY_GEN => (1, 512, 0x00008000),
        CKM_EC_KEY_PAIR_GEN => (256, 384, 0x00010000),
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 => (256, 384, 0x00000800 | 0x00002000),
        CKM_ECDH1_DERIVE => (256, 384, 0x00080000),
        CKM_EC_EDWARDS_KEY_PAIR_GEN => (255, 255, 0x00010000),
        CKM_EDDSA => (255, 255, 0x00000800 | 0x00002000),
        CKM_AES_KEY_GEN => (16, 32, 0x00008000),
        CKM_AES_GCM | CKM_AES_CBC_PAD => (16, 32, 0x00000100 | 0x00000200),
        CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP | CKM_AES_KEY_WRAP_PAD_LEGACY => {
            (16, 32, 0x00040000 | 0x00020000)
        }
        CKM_AES_CTR => (16, 32, 0x00000100 | 0x00000200),
        // ML-DSA pre-hash variants — same sign/verify capabilities as pure ML-DSA
        CKM_HASH_ML_DSA_SHA224
        | CKM_HASH_ML_DSA_SHA256
        | CKM_HASH_ML_DSA_SHA384
        | CKM_HASH_ML_DSA_SHA512
        | CKM_HASH_ML_DSA_SHA3_224
        | CKM_HASH_ML_DSA_SHA3_256
        | CKM_HASH_ML_DSA_SHA3_384
        | CKM_HASH_ML_DSA_SHA3_512
        | CKM_HASH_ML_DSA_SHAKE128
        | CKM_HASH_ML_DSA_SHAKE256 => (44, 87, 0x00000800 | 0x00002000),
        // SLH-DSA pre-hash variants — same sign/verify capabilities as pure SLH-DSA
        CKM_HASH_SLH_DSA_SHA224
        | CKM_HASH_SLH_DSA_SHA256
        | CKM_HASH_SLH_DSA_SHA384
        | CKM_HASH_SLH_DSA_SHA512
        | CKM_HASH_SLH_DSA_SHA3_224
        | CKM_HASH_SLH_DSA_SHA3_256
        | CKM_HASH_SLH_DSA_SHA3_384
        | CKM_HASH_SLH_DSA_SHA3_512
        | CKM_HASH_SLH_DSA_SHAKE128
        | CKM_HASH_SLH_DSA_SHAKE256 => (128, 256, 0x00000800 | 0x00002000),
        // ECDSA-SHA3 variants
        CKM_ECDSA_SHA3_224
        | CKM_ECDSA_SHA3_256
        | CKM_ECDSA_SHA3_384
        | CKM_ECDSA_SHA3_512 => (256, 384, 0x00000800 | 0x00002000),
        // ECDH cofactor derivation
        CKM_ECDH1_COFACTOR_DERIVE => (256, 384, 0x00080000),
        // Key derivation functions
        CKM_PKCS5_PBKD2
        | CKM_HKDF_DERIVE
        | CKM_SP800_108_COUNTER_KDF
        | CKM_SP800_108_FEEDBACK_KDF => (1, 512, 0x00080000),
        _ => return CKR_MECHANISM_INVALID,
    };
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = min_key;
        *ptr.add(1) = max_key;
        *ptr.add(2) = flags;
    }
    CKR_OK
}

// ── Key Generation ───────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_public_key_template: *mut u8,
    ul_public_key_attribute_count: u32,
    p_private_key_template: *mut u8,
    ul_private_key_attribute_count: u32,
    ph_public_key: *mut u32,
    ph_private_key: *mut u32,
) -> u32 {
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        match mech_type {
            CKM_ML_KEM_KEY_PAIR_GEN => {
                use ml_kem::{EncodedSizeUser, KemCore};
                use rand::rngs::OsRng;

                let ps = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                )
                .unwrap_or(CKP_ML_KEM_768);
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_KEM);
                store_algo_family(&mut prv_attrs, ALGO_ML_KEM);
                // PKCS#11 v3.2 defaults — ML-KEM public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_ML_KEM);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_KEM_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — ML-KEM private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_ML_KEM);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_KEM_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, false);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                let mut rng = OsRng;
                match ps {
                    CKP_ML_KEM_512 => {
                        let (dk, ek) = ml_kem::MlKem512::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    CKP_ML_KEM_768 => {
                        let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    CKP_ML_KEM_1024 => {
                        let (dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_ML_DSA_KEY_PAIR_GEN => {
                let ps = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                )
                .unwrap_or(CKP_ML_DSA_65);
                let mut seed_bytes = [0u8; 32];
                if getrandom::getrandom(&mut seed_bytes).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let seed: ml_dsa::Seed = seed_bytes.into();
                seed_bytes.zeroize();
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_DSA);
                store_algo_family(&mut prv_attrs, ALGO_ML_DSA);
                // PKCS#11 v3.2 defaults — ML-DSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_ML_DSA);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — ML-DSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_ML_DSA);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                match ps {
                    CKP_ML_DSA_44 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    CKP_ML_DSA_65 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    CKP_ML_DSA_87 => {
                        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
                        let vk = sk.verifying_key();
                        pub_attrs.insert(CKA_VALUE, vk.encode().as_slice().to_vec());
                        #[allow(deprecated)]
                        prv_attrs.insert(CKA_VALUE, sk.to_expanded().as_slice().to_vec());
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_SLH_DSA_KEY_PAIR_GEN => {
                let ps = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                )
                .unwrap_or(CKP_SLH_DSA_SHA2_128F);
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_SLH_DSA);
                store_algo_family(&mut prv_attrs, ALGO_SLH_DSA);
                // PKCS#11 v3.2 defaults — SLH-DSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_SLH_DSA);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_SLH_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — SLH-DSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_SLH_DSA);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_SLH_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                match ps {
                    CKP_SLH_DSA_SHA2_128S => {
                        slh_dsa_keygen!(slh_dsa::Sha2_128s, 16, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_128S => {
                        slh_dsa_keygen!(slh_dsa::Shake128s, 16, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_128F => {
                        slh_dsa_keygen!(slh_dsa::Sha2_128f, 16, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_128F => {
                        slh_dsa_keygen!(slh_dsa::Shake128f, 16, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_192S => {
                        slh_dsa_keygen!(slh_dsa::Sha2_192s, 24, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_192S => {
                        slh_dsa_keygen!(slh_dsa::Shake192s, 24, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_192F => {
                        slh_dsa_keygen!(slh_dsa::Sha2_192f, 24, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_192F => {
                        slh_dsa_keygen!(slh_dsa::Shake192f, 24, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_256S => {
                        slh_dsa_keygen!(slh_dsa::Sha2_256s, 32, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_256S => {
                        slh_dsa_keygen!(slh_dsa::Shake256s, 32, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_256F => {
                        slh_dsa_keygen!(slh_dsa::Sha2_256f, 32, pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_256F => {
                        slh_dsa_keygen!(slh_dsa::Shake256f, 32, pub_attrs, prv_attrs)
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                let bits = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_MODULUS_BITS,
                )
                .unwrap_or(2048) as usize;
                if !(2048..=4096).contains(&bits) {
                    return CKR_ARGUMENTS_BAD;
                }
                let mut rng = rand::rngs::OsRng;
                let private_key = match rsa::RsaPrivateKey::new(&mut rng, bits) {
                    Ok(k) => k,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                let public_key = rsa::RsaPublicKey::from(&private_key);

                use rsa::pkcs8::EncodePrivateKey;
                let sk_der = match private_key.to_pkcs8_der() {
                    Ok(d) => d,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };

                // Public key: [n_len:4LE][n_bytes][e_bytes]
                use rsa::traits::PublicKeyParts;
                let n_bytes = public_key.n().to_bytes_be();
                let e_bytes = public_key.e().to_bytes_be();
                let mut pk_bytes = Vec::with_capacity(4 + n_bytes.len() + e_bytes.len());
                pk_bytes.extend_from_slice(&(n_bytes.len() as u32).to_le_bytes());
                pk_bytes.extend_from_slice(&n_bytes);
                pk_bytes.extend_from_slice(&e_bytes);

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_RSA);
                store_algo_family(&mut prv_attrs, ALGO_RSA);
                // PKCS#11 v3.2 defaults — RSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_RSA);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, true);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_RSA_PKCS_KEY_PAIR_GEN,
                );
                // PKCS#11 v3.2 defaults — RSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_RSA);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, true);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_RSA_PKCS_KEY_PAIR_GEN,
                );
                // SubjectPublicKeyInfo DER (CKA_PUBLIC_KEY_INFO)
                {
                    use rsa::pkcs8::EncodePublicKey;
                    if let Ok(spki_der) = public_key.to_public_key_der() {
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki_der.as_bytes().to_vec());
                    }
                }
                pub_attrs.insert(CKA_VALUE, pk_bytes);
                prv_attrs.insert(CKA_VALUE, sk_der.as_bytes().to_vec());
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_EC_KEY_PAIR_GEN => {
                let mut rng = rand::rngs::OsRng;
                let ec_params = get_attr_bytes(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_EC_PARAMS,
                );
                let is_p384 = ec_params
                    .as_ref()
                    .is_some_and(|b| b.len() >= 7 && b[b.len() - 1] == 0x22);

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_ECDSA);
                store_algo_family(&mut prv_attrs, ALGO_ECDSA);
                // PKCS#11 v3.2 defaults — ECDSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
                // PKCS#11 v3.2 defaults — ECDSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, true); // supports ECDH
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);

                if is_p384 {
                    store_param_set(&mut pub_attrs, CURVE_P384);
                    store_param_set(&mut prv_attrs, CURVE_P384);
                    let sk = p384::ecdsa::SigningKey::random(&mut rng);
                    let vk = p384::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    pub_attrs.insert(CKA_VALUE, vk_bytes.clone());
                    pub_attrs.insert(CKA_EC_POINT, vk_bytes.clone());
                    // SubjectPublicKeyInfo DER for P-384 (97-byte uncompressed point)
                    // 30 76 30 10 06 07 2a86 48ce3d0201 06 05 2b81 0400 22 03 62 00 <97 bytes>
                    let spki = build_ec_spki_p384(&vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                } else {
                    store_param_set(&mut pub_attrs, CURVE_P256);
                    store_param_set(&mut prv_attrs, CURVE_P256);
                    let sk = p256::ecdsa::SigningKey::random(&mut rng);
                    let vk = p256::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    pub_attrs.insert(CKA_VALUE, vk_bytes.clone());
                    pub_attrs.insert(CKA_EC_POINT, vk_bytes.clone());
                    // SubjectPublicKeyInfo DER for P-256 (65-byte uncompressed point)
                    // 30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 <65 bytes>
                    let spki = build_ec_spki_p256(&vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            CKM_EC_EDWARDS_KEY_PAIR_GEN => {
                let mut rng = rand::rngs::OsRng;
                let sk = ed25519_dalek::SigningKey::generate(&mut rng);
                let vk = sk.verifying_key();

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_EDDSA);
                store_algo_family(&mut prv_attrs, ALGO_EDDSA);
                // PKCS#11 v3.2 defaults — EdDSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_EDWARDS_KEY_PAIR_GEN,
                );
                // PKCS#11 v3.2 defaults — EdDSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_EDWARDS_KEY_PAIR_GEN,
                );
                let vk_bytes = vk.to_bytes().to_vec();
                prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                pub_attrs.insert(CKA_VALUE, vk_bytes.clone());
                // SubjectPublicKeyInfo DER for Ed25519 (32-byte key)
                // 30 2a 30 05 06 03 2b6570 03 22 00 <32 bytes>
                let spki = build_ed25519_spki(&vk_bytes);
                pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                *ph_public_key = allocate_handle(pub_attrs);
                *ph_private_key = allocate_handle(prv_attrs);
                CKR_OK
            }

            _ => CKR_MECHANISM_INVALID,
        }
    }
}

#[wasm_bindgen(js_name = _C_GenerateKey)]
pub fn C_GenerateKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_template: *mut u8,
    ul_count: u32,
    ph_key: *mut u32,
) -> u32 {
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        match mech_type {
            CKM_AES_KEY_GEN => {
                let key_len =
                    get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(16) as usize;
                if key_len != 16 && key_len != 32 {
                    return CKR_ARGUMENTS_BAD;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                // PKCS#11 v3.2 defaults — AES secret key
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
                store_ulong(&mut attrs, CKA_VALUE_LEN, key_len as u32);
                store_bool(&mut attrs, CKA_TOKEN, false);
                store_bool(&mut attrs, CKA_PRIVATE, false);
                store_bool(&mut attrs, CKA_SENSITIVE, false);
                store_bool(&mut attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut attrs, CKA_ENCRYPT, true);
                store_bool(&mut attrs, CKA_DECRYPT, true);
                store_bool(&mut attrs, CKA_WRAP, true);
                store_bool(&mut attrs, CKA_UNWRAP, true);
                store_bool(&mut attrs, CKA_SIGN, false);
                store_bool(&mut attrs, CKA_VERIFY, false);
                store_bool(&mut attrs, CKA_DERIVE, false);
                store_bool(&mut attrs, CKA_LOCAL, true);
                absorb_template_attrs(&mut attrs, p_template, ul_count);
                *ph_key = allocate_handle(attrs);
                CKR_OK
            }
            CKM_GENERIC_SECRET_KEY_GEN => {
                let key_len =
                    get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(32) as usize;
                if key_len == 0 || key_len > 512 {
                    return CKR_ARGUMENTS_BAD;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                // PKCS#11 v3.2 defaults — GENERIC_SECRET key (used for HMAC)
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_ulong(&mut attrs, CKA_VALUE_LEN, key_len as u32);
                store_bool(&mut attrs, CKA_TOKEN, false);
                store_bool(&mut attrs, CKA_SENSITIVE, false);
                store_bool(&mut attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut attrs, CKA_ENCRYPT, false);
                store_bool(&mut attrs, CKA_DECRYPT, false);
                store_bool(&mut attrs, CKA_WRAP, false);
                store_bool(&mut attrs, CKA_UNWRAP, false);
                store_bool(&mut attrs, CKA_SIGN, true); // HMAC signing
                store_bool(&mut attrs, CKA_VERIFY, true);
                store_bool(&mut attrs, CKA_DERIVE, false);
                store_bool(&mut attrs, CKA_LOCAL, true);
                absorb_template_attrs(&mut attrs, p_template, ul_count);
                *ph_key = allocate_handle(attrs);
                CKR_OK
            }
            _ => CKR_MECHANISM_INVALID,
        }
    }
}

// ── ML-KEM Encapsulate/Decapsulate ──────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncapsulateKey)]
pub fn C_EncapsulateKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_key: u32,
    _p_template: *mut u8,
    _ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    pul_ciphertext_len: *mut u32,
    ph_key: *mut u32,
) -> u32 {
    use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore};
    use rand::rngs::OsRng;

    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }

        let ps = get_object_param_set(h_key);
        let ct_len: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 | 0 => 1088,
            CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if p_ciphertext.is_null() {
            *pul_ciphertext_len = ct_len;
            return CKR_OK;
        }
        if *pul_ciphertext_len < ct_len {
            *pul_ciphertext_len = ct_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        let pub_key_bytes = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let mut rng = OsRng;

        macro_rules! encap {
            ($kem:ty) => {{
                let ek_enc = match ml_kem::array::Array::try_from(pub_key_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let ek = <$kem as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
                let (ct, ss) = match Encapsulate::encapsulate(&ek, &mut rng) {
                    Ok(r) => r,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                std::ptr::copy_nonoverlapping(
                    ct.as_slice().as_ptr(),
                    p_ciphertext,
                    ct_len as usize,
                );
                *pul_ciphertext_len = ct_len;
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                *ph_key = allocate_handle(ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => encap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 | 0 => encap!(ml_kem::MlKem768),
            CKP_ML_KEM_1024 => encap!(ml_kem::MlKem1024),
            _ => return CKR_ARGUMENTS_BAD,
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecapsulateKey)]
pub fn C_DecapsulateKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_private_key: u32,
    _p_template: *mut u8,
    _ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    ul_ciphertext_len: u32,
    ph_key: *mut u32,
) -> u32 {
    use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore};

    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }

        let ps = get_object_param_set(h_private_key);
        let expected_ct: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 | 0 => 1088,
            CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if ul_ciphertext_len != expected_ct {
            return CKR_ARGUMENTS_BAD;
        }

        let prv_key_bytes = match get_object_value(h_private_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let ct_bytes =
            std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize).to_vec();

        macro_rules! decap {
            ($kem:ty) => {{
                let dk_enc = match ml_kem::array::Array::try_from(prv_key_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let dk = <$kem as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
                let ct_enc = match ml_kem::array::Array::try_from(ct_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let ss = match Decapsulate::decapsulate(&dk, &ct_enc) {
                    Ok(s) => s,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                *ph_key = allocate_handle(ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => decap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 | 0 => decap!(ml_kem::MlKem768),
            CKP_ML_KEM_1024 => decap!(ml_kem::MlKem1024),
            _ => return CKR_ARGUMENTS_BAD,
        }
    }
    CKR_OK
}

// ── Object Operations ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GetAttributeValue)]
pub fn C_GetAttributeValue(_h_session: u32, h_object: u32, p_template: *mut u8, count: u32) -> u32 {
    let attrs = OBJECTS.with(|o| o.borrow().get(&h_object).cloned());
    if let Some(obj_attrs) = attrs {
        let sensitive = read_bool_attr(&obj_attrs, CKA_SENSITIVE);
        let extractable = read_bool_attr(&obj_attrs, CKA_EXTRACTABLE);
        unsafe {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *mut u8;
                let val_len_ptr = tmpl_ptr.add((i * 3 + 2) as usize);
                // Block CKA_VALUE access for sensitive or non-extractable keys
                if attr_type == CKA_VALUE && (sensitive || !extractable) {
                    *val_len_ptr = 0xFFFFFFFF; // CK_UNAVAILABLE_INFORMATION
                    continue;
                }
                if let Some(val) = obj_attrs.get(&attr_type) {
                    if val_ptr.is_null() {
                        *val_len_ptr = val.len() as u32;
                    } else if *val_len_ptr >= val.len() as u32 {
                        std::ptr::copy_nonoverlapping(val.as_ptr(), val_ptr, val.len());
                        *val_len_ptr = val.len() as u32;
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
            }
        }
        CKR_OK
    } else {
        CKR_ARGUMENTS_BAD
    }
}

#[wasm_bindgen(js_name = _C_CreateObject)]
pub fn C_CreateObject(
    _h_session: u32,
    p_template: *mut u8,
    count: u32,
    ph_object: *mut u32,
) -> u32 {
    unsafe {
        if count > 65536 {
            return CKR_ARGUMENTS_BAD;
        }
        let tmpl_ptr = p_template as *mut u32;
        let mut new_attrs = HashMap::new();
        for i in 0..count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize);
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
            if !val_ptr.is_null() && val_len > 0 {
                let mut v = vec![0u8; val_len as usize];
                std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                new_attrs.insert(attr_type, v);
            }
        }
        if let Some(ps_bytes) = new_attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut new_attrs, ps);
            }
        }
        *ph_object = allocate_handle(new_attrs);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DestroyObject)]
pub fn C_DestroyObject(_h_session: u32, h_object: u32) -> u32 {
    let removed = OBJECTS.with(|objs| objs.borrow_mut().remove(&h_object).is_some());
    if removed {
        // PKCS#11 v3.2: clean up any active operation state referencing the destroyed key.
        // Without this, a session that called C_SignInit then C_DestroyObject would hold a
        // stale key handle, causing undefined behaviour on the subsequent C_Sign call.
        SIGN_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != h_object));
        VERIFY_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != h_object));
        ENCRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != h_object));
        DECRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != h_object));
        CKR_OK
    } else {
        CKR_OBJECT_HANDLE_INVALID
    }
}

// ── Sign/Verify ─────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_SignInit)]
pub fn C_SignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4: check CKA_SIGN permission
        let can_sign = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_SIGN))
                .unwrap_or(false)
        });
        if !can_sign {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let mut mech_type = *(p_mechanism as *const u32);
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            if !p_param.is_null() && ul_param_len >= 4 {
                let ph_flag = *(p_param as *const u32);
                if ph_flag != 0 {
                    mech_type = CKM_EDDSA_PH;
                }
            }
        }
        SIGN_STATE.with(|s| {
            s.borrow_mut().insert(h_session, (mech_type, h_key));
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Sign)]
pub fn C_Sign(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    // Peek first to support the size-query path (p_signature == null) without consuming state.
    let state = SIGN_STATE.with(|s| s.borrow().get(&h_session).copied());
    let (mech, hkey) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    unsafe {
        if p_signature.is_null() {
            *pul_signature_len = get_sig_len(mech, hkey);
            return CKR_OK;
        }

        let sk_bytes = match get_object_value(hkey) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ps = get_object_param_set(hkey);

        // Pre-hash dispatch: CKM_HASH_ML_DSA_* and CKM_HASH_SLH_DSA_* hash msg first,
        // then sign the digest as if it were plain CKM_ML_DSA / CKM_SLH_DSA.
        let eff_mech: u32;
        let hash_buf: Vec<u8>;
        let eff_msg: &[u8];
        if is_prehash_ml_dsa(mech) {
            hash_buf = match prehash_message(mech, msg) {
                Some(h) => h,
                None => return CKR_MECHANISM_INVALID,
            };
            eff_mech = CKM_ML_DSA;
            eff_msg = &hash_buf;
        } else if is_prehash_slh_dsa(mech) {
            hash_buf = match prehash_message(mech, msg) {
                Some(h) => h,
                None => return CKR_MECHANISM_INVALID,
            };
            eff_mech = CKM_SLH_DSA;
            eff_msg = &hash_buf;
        } else {
            hash_buf = Vec::new();
            eff_mech = mech;
            eff_msg = msg;
        }
        let _ = &hash_buf; // suppress unused warning when pre-hash path not taken

        let result = match eff_mech {
            CKM_ML_DSA => sign_ml_dsa(ps, &sk_bytes, eff_msg),
            CKM_SLH_DSA => sign_slh_dsa(ps, &sk_bytes, eff_msg),
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC => sign_hmac(eff_mech, &sk_bytes, eff_msg),
            CKM_KMAC_128 | CKM_KMAC_256 => sign_kmac(eff_mech, &sk_bytes, eff_msg),
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => sign_rsa(eff_mech, &sk_bytes, eff_msg),
            CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256
            | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
                sign_ecdsa(eff_mech, ps, &sk_bytes, eff_msg)
            }
            CKM_EDDSA => sign_eddsa(&sk_bytes, eff_msg),
            CKM_EDDSA_PH => sign_eddsa_ph(&sk_bytes, eff_msg),
            _ => Err(CKR_MECHANISM_INVALID),
        };

        let rv = match result {
            Ok(sig) => {
                if (*pul_signature_len as usize) < sig.len() {
                    *pul_signature_len = sig.len() as u32;
                    return CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                *pul_signature_len = sig.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        };
        // Consume sign state after the actual sign (not the size-query path above)
        SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
        rv
    }
}

#[wasm_bindgen(js_name = _C_VerifyInit)]
pub fn C_VerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4: check CKA_VERIFY permission
        let can_verify = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_VERIFY))
                .unwrap_or(false)
        });
        if !can_verify {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let mut mech_type = *(p_mechanism as *const u32);
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            if !p_param.is_null() && ul_param_len >= 4 {
                let ph_flag = *(p_param as *const u32);
                if ph_flag != 0 {
                    mech_type = CKM_EDDSA_PH;
                }
            }
        }
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(h_session, (mech_type, h_key));
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Verify)]
pub fn C_Verify(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    let state = VERIFY_STATE.with(|s| s.borrow().get(&h_session).copied());
    let (mech, hkey) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    unsafe {
        let pk_bytes = match get_object_value(hkey) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let sig_bytes = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
        let ps = get_object_param_set(hkey);

        // Pre-hash dispatch: same logic as C_Sign
        let eff_mech: u32;
        let hash_buf: Vec<u8>;
        let eff_msg: &[u8];
        if is_prehash_ml_dsa(mech) {
            hash_buf = match prehash_message(mech, msg) {
                Some(h) => h,
                None => return CKR_MECHANISM_INVALID,
            };
            eff_mech = CKM_ML_DSA;
            eff_msg = &hash_buf;
        } else if is_prehash_slh_dsa(mech) {
            hash_buf = match prehash_message(mech, msg) {
                Some(h) => h,
                None => return CKR_MECHANISM_INVALID,
            };
            eff_mech = CKM_SLH_DSA;
            eff_msg = &hash_buf;
        } else {
            hash_buf = Vec::new();
            eff_mech = mech;
            eff_msg = msg;
        }
        let _ = &hash_buf;

        let rv = match match eff_mech {
            CKM_ML_DSA => verify_ml_dsa(ps, &pk_bytes, eff_msg, sig_bytes),
            CKM_SLH_DSA => verify_slh_dsa(ps, &pk_bytes, eff_msg, sig_bytes),
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC => verify_hmac(eff_mech, &pk_bytes, eff_msg, sig_bytes),
            CKM_KMAC_128 | CKM_KMAC_256 => match sign_kmac(eff_mech, &pk_bytes, eff_msg) {
                Ok(sig) => {
                    if sig == sig_bytes {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                Err(e) => Err(e),
            },
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => {
                verify_rsa(eff_mech, &pk_bytes, eff_msg, sig_bytes)
            }
            CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256
            | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
                verify_ecdsa(eff_mech, ps, &pk_bytes, eff_msg, sig_bytes)
            }
            CKM_EDDSA => verify_eddsa(&pk_bytes, eff_msg, sig_bytes),
            CKM_EDDSA_PH => verify_eddsa_ph(&pk_bytes, eff_msg, sig_bytes),
            _ => Err(CKR_MECHANISM_INVALID),
        } {
            Ok(()) => CKR_OK,
            Err(e) => e,
        };
        // Consume verify state after the actual verify operation
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
        rv
    }
}

// ── Message-based Sign/Verify API ───────────────────────────────────────────

#[wasm_bindgen(js_name = _C_MessageSignInit)]
pub fn C_MessageSignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    C_SignInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_SignMessage)]
pub fn C_SignMessage(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    let saved = SIGN_STATE.with(|s| s.borrow().get(&h_session).copied());
    let rv = C_Sign(
        h_session,
        p_data,
        ul_data_len,
        p_signature,
        pul_signature_len,
    );
    if let Some(st) = saved {
        SIGN_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    rv
}

#[wasm_bindgen(js_name = _C_MessageSignFinal)]
pub fn C_MessageSignFinal(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    _p_signature: *mut u8,
    _pul_signature_len: *mut u32,
) -> u32 {
    SIGN_STATE.with(|s| {
        s.borrow_mut().remove(&h_session);
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_MessageVerifyInit)]
pub fn C_MessageVerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    C_VerifyInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_VerifyMessage)]
pub fn C_VerifyMessage(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    let saved = VERIFY_STATE.with(|s| s.borrow().get(&h_session).copied());
    let rv = C_Verify(
        h_session,
        p_data,
        ul_data_len,
        p_signature,
        ul_signature_len,
    );
    if let Some(st) = saved {
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    rv
}

#[wasm_bindgen(js_name = _C_MessageVerifyFinal)]
pub fn C_MessageVerifyFinal(h_session: u32) -> u32 {
    VERIFY_STATE.with(|s| {
        s.borrow_mut().remove(&h_session);
    });
    CKR_OK
}

// ── Encrypt/Decrypt ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncryptInit)]
pub fn C_EncryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4: check CKA_ENCRYPT permission
        let can_encrypt = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_ENCRYPT))
                .unwrap_or(false)
        });
        if !can_encrypt {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_ARGUMENTS_BAD;
                }
                let gcm = p_param as *const u32;
                let iv_ptr = *gcm as usize as *const u8;
                let iv_len = *gcm.add(1) as usize;
                let tag_bits = *gcm.add(4);
                let iv = if !iv_ptr.is_null() && iv_len > 0 {
                    if iv_len != 12 {
                        return CKR_ARGUMENTS_BAD; // AES-GCM requires exactly 12-byte nonce
                    }
                    std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
                } else {
                    vec![0u8; 12]
                };
                (iv, Vec::new(), tag_bits)
            }
            CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 {
                    return CKR_ARGUMENTS_BAD;
                }
                (
                    std::slice::from_raw_parts(p_param, 16).to_vec(),
                    Vec::new(),
                    0,
                )
            }
            CKM_AES_CTR => {
                // CK_AES_CTR_PARAMS: ulCounterBits(CK_ULONG=4) + cb[16] = 20 bytes min
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_ARGUMENTS_BAD;
                }
                // cb is at offset 4 (after ulCounterBits)
                let counter_block = std::slice::from_raw_parts(p_param.add(4), 16).to_vec();
                (counter_block, Vec::new(), 0)
            }
            CKM_RSA_PKCS_OAEP => {
                // CK_RSA_PKCS_OAEP_PARAMS: hashAlg(4) + mgf(4) + source(4) + ...
                let hash_alg = if !p_param.is_null() && ul_param_len >= 4 {
                    *(p_param as *const u32)
                } else {
                    CKM_SHA256 // default
                };
                (Vec::new(), Vec::new(), hash_alg)
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        ENCRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                EncryptCtx {
                    mech_type,
                    key_handle: h_key,
                    iv,
                    aad,
                    tag_bits,
                },
            );
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Encrypt)]
pub fn C_Encrypt(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_encrypted_data: *mut u8,
    pul_encrypted_data_len: *mut u32,
) -> u32 {
    // Remove state on entry — consumed on all paths except null-buffer size query
    let ctx = ENCRYPT_STATE.with(|s| {
        s.borrow_mut()
            .remove(&h_session)
            .map(|c| (c.mech_type, c.key_handle, c.iv, c.tag_bits))
    });
    let (mech_type, key_handle, iv, tag_bits) = match ctx {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    unsafe {
        let plaintext = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ct = match mech_type {
            CKM_AES_GCM => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
                let nonce = GenericArray::from_slice(&iv);
                let result = match key_bytes.len() {
                    16 => Aes128Gcm::new_from_slice(&key_bytes)
                        .unwrap()
                        .encrypt(nonce, plaintext),
                    32 => Aes256Gcm::new_from_slice(&key_bytes)
                        .unwrap()
                        .encrypt(nonce, plaintext),
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                match result {
                    Ok(ct) => ct,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
                type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
                let padded_len = plaintext.len() + 16 - (plaintext.len() % 16);
                let mut buf = vec![0u8; padded_len];
                buf[..plaintext.len()].copy_from_slice(plaintext);
                match key_bytes.len() {
                    16 => match Aes128CbcEnc::new_from_slices(&key_bytes, &iv)
                        .unwrap()
                        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                    {
                        Ok(ct) => ct.to_vec(),
                        Err(_) => return CKR_FUNCTION_FAILED,
                    },
                    32 => match Aes256CbcEnc::new_from_slices(&key_bytes, &iv)
                        .unwrap()
                        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                    {
                        Ok(ct) => ct.to_vec(),
                        Err(_) => return CKR_FUNCTION_FAILED,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                }
            }
            CKM_AES_CTR => {
                // CTR mode is its own inverse — same code path for encrypt/decrypt
                use aes::cipher::{KeyIvInit, StreamCipher};
                type Ctr128BE128 = ctr::Ctr128BE<aes::Aes128>;
                type Ctr128BE256 = ctr::Ctr128BE<aes::Aes256>;
                let mut buf = plaintext.to_vec();
                match key_bytes.len() {
                    16 => match Ctr128BE128::new_from_slices(&key_bytes, &iv) {
                        Ok(mut cipher) => cipher.apply_keystream(&mut buf),
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    32 => match Ctr128BE256::new_from_slices(&key_bytes, &iv) {
                        Ok(mut cipher) => cipher.apply_keystream(&mut buf),
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                }
                buf
            }
            CKM_RSA_PKCS_OAEP => {
                if key_bytes.len() < 8 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n_len =
                    u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]])
                        as usize;
                if key_bytes.len() < 4 + n_len + 1 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n = rsa::BigUint::from_bytes_be(&key_bytes[4..4 + n_len]);
                let e = rsa::BigUint::from_bytes_be(&key_bytes[4 + n_len..]);
                let pk = match rsa::RsaPublicKey::new(n, e) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let mut rng = rand::rngs::OsRng;
                let oaep = match tag_bits {
                    CKM_SHA384 => rsa::Oaep::new::<sha2::Sha384>(),
                    CKM_SHA512 => rsa::Oaep::new::<sha2::Sha512>(),
                    _ => rsa::Oaep::new::<sha2::Sha256>(),
                };
                match pk.encrypt(&mut rng, oaep, plaintext) {
                    Ok(ct) => ct,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        if p_encrypted_data.is_null() {
            *pul_encrypted_data_len = ct.len() as u32;
            // Re-insert state for size-query (per PKCS#11: operation not terminated)
            ENCRYPT_STATE.with(|s| {
                s.borrow_mut().insert(
                    h_session,
                    EncryptCtx {
                        mech_type,
                        key_handle,
                        iv,
                        aad: Vec::new(),
                        tag_bits,
                    },
                );
            });
            return CKR_OK;
        }
        if (*pul_encrypted_data_len as usize) < ct.len() {
            *pul_encrypted_data_len = ct.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(ct.as_ptr(), p_encrypted_data, ct.len());
        *pul_encrypted_data_len = ct.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecryptInit)]
pub fn C_DecryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4: check CKA_DECRYPT permission
        let can_decrypt = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_DECRYPT))
                .unwrap_or(false)
        });
        if !can_decrypt {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_ARGUMENTS_BAD;
                }
                let gcm = p_param as *const u32;
                let iv_ptr = *gcm as usize as *const u8;
                let iv_len = *gcm.add(1) as usize;
                let tag_bits = *gcm.add(4);
                let iv = if !iv_ptr.is_null() && iv_len > 0 {
                    if iv_len != 12 {
                        return CKR_ARGUMENTS_BAD; // AES-GCM requires exactly 12-byte nonce
                    }
                    std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
                } else {
                    vec![0u8; 12]
                };
                (iv, Vec::new(), tag_bits)
            }
            CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 {
                    return CKR_ARGUMENTS_BAD;
                }
                (
                    std::slice::from_raw_parts(p_param, 16).to_vec(),
                    Vec::new(),
                    0,
                )
            }
            CKM_AES_CTR => {
                // CK_AES_CTR_PARAMS: ulCounterBits(4) + cb[16] = 20 bytes min
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_ARGUMENTS_BAD;
                }
                let counter_block = std::slice::from_raw_parts(p_param.add(4), 16).to_vec();
                (counter_block, Vec::new(), 0)
            }
            CKM_RSA_PKCS_OAEP => {
                let hash_alg = if !p_param.is_null() && ul_param_len >= 4 {
                    *(p_param as *const u32)
                } else {
                    CKM_SHA256
                };
                (Vec::new(), Vec::new(), hash_alg)
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        DECRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                EncryptCtx {
                    mech_type,
                    key_handle: h_key,
                    iv,
                    aad,
                    tag_bits,
                },
            );
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Decrypt)]
pub fn C_Decrypt(
    h_session: u32,
    p_encrypted_data: *mut u8,
    ul_encrypted_data_len: u32,
    p_data: *mut u8,
    pul_data_len: *mut u32,
) -> u32 {
    // Remove state on entry — consumed on all paths except null-buffer size query
    let ctx = DECRYPT_STATE.with(|s| {
        s.borrow_mut()
            .remove(&h_session)
            .map(|c| (c.mech_type, c.key_handle, c.iv, c.tag_bits))
    });
    let (mech_type, key_handle, iv, tag_bits) = match ctx {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    unsafe {
        let ciphertext =
            std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize);
        let pt = match mech_type {
            CKM_AES_GCM => {
                use aes_gcm::aead::generic_array::GenericArray;
                use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
                let nonce = GenericArray::from_slice(&iv);
                let result = match key_bytes.len() {
                    16 => Aes128Gcm::new_from_slice(&key_bytes)
                        .unwrap()
                        .decrypt(nonce, ciphertext),
                    32 => Aes256Gcm::new_from_slice(&key_bytes)
                        .unwrap()
                        .decrypt(nonce, ciphertext),
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                match result {
                    Ok(pt) => pt,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
                type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
                let mut buf = ciphertext.to_vec();
                let pt_slice: &[u8] = match key_bytes.len() {
                    16 => match Aes128CbcDec::new_from_slices(&key_bytes, &iv)
                        .unwrap()
                        .decrypt_padded_mut::<Pkcs7>(&mut buf)
                    {
                        Ok(pt) => pt,
                        Err(_) => return CKR_FUNCTION_FAILED,
                    },
                    32 => match Aes256CbcDec::new_from_slices(&key_bytes, &iv)
                        .unwrap()
                        .decrypt_padded_mut::<Pkcs7>(&mut buf)
                    {
                        Ok(pt) => pt,
                        Err(_) => return CKR_FUNCTION_FAILED,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                pt_slice.to_vec()
            }
            CKM_AES_CTR => {
                // CTR mode is its own inverse
                use aes::cipher::{KeyIvInit, StreamCipher};
                type Ctr128BE128 = ctr::Ctr128BE<aes::Aes128>;
                type Ctr128BE256 = ctr::Ctr128BE<aes::Aes256>;
                let mut buf = ciphertext.to_vec();
                match key_bytes.len() {
                    16 => match Ctr128BE128::new_from_slices(&key_bytes, &iv) {
                        Ok(mut cipher) => cipher.apply_keystream(&mut buf),
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    32 => match Ctr128BE256::new_from_slices(&key_bytes, &iv) {
                        Ok(mut cipher) => cipher.apply_keystream(&mut buf),
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                }
                buf
            }
            CKM_RSA_PKCS_OAEP => {
                use rsa::pkcs8::DecodePrivateKey;
                let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&key_bytes) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let oaep = match tag_bits {
                    CKM_SHA384 => rsa::Oaep::new::<sha2::Sha384>(),
                    CKM_SHA512 => rsa::Oaep::new::<sha2::Sha512>(),
                    _ => rsa::Oaep::new::<sha2::Sha256>(),
                };
                match sk.decrypt(oaep, ciphertext) {
                    Ok(pt) => pt,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        if p_data.is_null() {
            *pul_data_len = pt.len() as u32;
            // Re-insert state for size-query (per PKCS#11: operation not terminated)
            DECRYPT_STATE.with(|s| {
                s.borrow_mut().insert(
                    h_session,
                    EncryptCtx {
                        mech_type,
                        key_handle,
                        iv,
                        aad: Vec::new(),
                        tag_bits,
                    },
                );
            });
            return CKR_OK;
        }
        if (*pul_data_len as usize) < pt.len() {
            *pul_data_len = pt.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(pt.as_ptr(), p_data, pt.len());
        *pul_data_len = pt.len() as u32;
    }
    CKR_OK
}

// ── SHA Digest ──────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_DigestInit)]
pub fn C_DigestInit(h_session: u32, p_mechanism: *mut u8) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        use sha2::Digest;
        let ctx = match mech_type {
            CKM_SHA256 => DigestCtx::Sha256(sha2::Sha256::new()),
            CKM_SHA384 => DigestCtx::Sha384(sha2::Sha384::new()),
            CKM_SHA512 => DigestCtx::Sha512(sha2::Sha512::new()),
            CKM_SHA3_256 => DigestCtx::Sha3_256(sha3::Sha3_256::new()),
            CKM_SHA3_512 => DigestCtx::Sha3_512(sha3::Sha3_512::new()),
            _ => return CKR_MECHANISM_INVALID,
        };
        DIGEST_STATE.with(|s| {
            s.borrow_mut().insert(h_session, ctx);
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestUpdate)]
pub fn C_DigestUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    use sha2::Digest;
    let has_state = DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session));
    if !has_state {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    unsafe {
        let data = std::slice::from_raw_parts(p_part, ul_part_len as usize);
        DIGEST_STATE.with(|s| {
            let mut map = s.borrow_mut();
            if let Some(ctx) = map.get_mut(&h_session) {
                match ctx {
                    DigestCtx::Sha256(h) => h.update(data),
                    DigestCtx::Sha384(h) => h.update(data),
                    DigestCtx::Sha512(h) => h.update(data),
                    DigestCtx::Sha3_256(h) => h.update(data),
                    DigestCtx::Sha3_512(h) => h.update(data),
                }
            }
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestFinal)]
pub fn C_DigestFinal(h_session: u32, p_digest: *mut u8, pul_digest_len: *mut u32) -> u32 {
    unsafe {
        // Size-only query: return expected length WITHOUT consuming state.
        // Per PKCS#11 v3.2 §5.7.2, a null pDigest must not terminate the operation.
        if p_digest.is_null() {
            let len = DIGEST_STATE.with(|s| {
                s.borrow().get(&h_session).map(|ctx| match ctx {
                    DigestCtx::Sha256(_) => 32u32,
                    DigestCtx::Sha384(_) => 48,
                    DigestCtx::Sha512(_) => 64,
                    DigestCtx::Sha3_256(_) => 32,
                    DigestCtx::Sha3_512(_) => 64,
                })
            });
            return match len {
                Some(l) => {
                    *pul_digest_len = l;
                    CKR_OK
                }
                None => CKR_OPERATION_NOT_INITIALIZED,
            };
        }
        // Consume state and produce digest.
        use sha2::Digest;
        let ctx = DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
        let ctx = match ctx {
            Some(c) => c,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };
        let hash = match ctx {
            DigestCtx::Sha256(h) => h.finalize().to_vec(),
            DigestCtx::Sha384(h) => h.finalize().to_vec(),
            DigestCtx::Sha512(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_256(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_512(h) => h.finalize().to_vec(),
        };
        if (*pul_digest_len as usize) < hash.len() {
            *pul_digest_len = hash.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(hash.as_ptr(), p_digest, hash.len());
        *pul_digest_len = hash.len() as u32;
        CKR_OK
    }
}

#[wasm_bindgen(js_name = _C_Digest)]
pub fn C_Digest(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_digest: *mut u8,
    pul_digest_len: *mut u32,
) -> u32 {
    unsafe {
        // Size-only query: return expected length WITHOUT updating state.
        // Per PKCS#11 v3.2 §5.7.2, data must not be processed on a null-pDigest call.
        if p_digest.is_null() {
            let len = DIGEST_STATE.with(|s| {
                s.borrow().get(&h_session).map(|ctx| match ctx {
                    DigestCtx::Sha256(_) => 32u32,
                    DigestCtx::Sha384(_) => 48,
                    DigestCtx::Sha512(_) => 64,
                    DigestCtx::Sha3_256(_) => 32,
                    DigestCtx::Sha3_512(_) => 64,
                })
            });
            return match len {
                Some(l) => {
                    *pul_digest_len = l;
                    CKR_OK
                }
                None => CKR_OPERATION_NOT_INITIALIZED,
            };
        }
        let rv = C_DigestUpdate(h_session, p_data, ul_data_len);
        if rv != CKR_OK {
            return rv;
        }
        C_DigestFinal(h_session, p_digest, pul_digest_len)
    }
}

// ── FindObjects ─────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_FindObjectsInit)]
pub fn C_FindObjectsInit(h_session: u32, p_template: *mut u8, ul_count: u32) -> u32 {
    let mut match_attrs: Vec<(u32, Vec<u8>)> = Vec::new();
    unsafe {
        if !p_template.is_null() && ul_count > 0 && ul_count <= 65536 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as usize;
                if !val_ptr.is_null() && val_len > 0 {
                    match_attrs.push((
                        attr_type,
                        std::slice::from_raw_parts(val_ptr, val_len).to_vec(),
                    ));
                }
            }
        }
    }
    let matching = OBJECTS.with(|objs| {
        objs.borrow()
            .iter()
            .filter(|(_, attrs)| {
                match_attrs
                    .iter()
                    .all(|(typ, val)| attrs.get(typ) == Some(val))
            })
            .map(|(handle, _)| *handle)
            .collect::<Vec<u32>>()
    });
    FIND_STATE.with(|s| {
        s.borrow_mut().insert(
            h_session,
            FindCtx {
                handles: matching,
                cursor: 0,
            },
        );
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_FindObjects)]
pub fn C_FindObjects(
    h_session: u32,
    ph_object: *mut u32,
    ul_max_object_count: u32,
    pul_object_count: *mut u32,
) -> u32 {
    FIND_STATE.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(ctx) = map.get_mut(&h_session) {
            let remaining = ctx.handles.len() - ctx.cursor;
            let count = remaining.min(ul_max_object_count as usize);
            unsafe {
                for i in 0..count {
                    *ph_object.add(i) = ctx.handles[ctx.cursor + i];
                }
                *pul_object_count = count as u32;
            }
            ctx.cursor += count;
            CKR_OK
        } else {
            CKR_OPERATION_NOT_INITIALIZED
        }
    })
}

#[wasm_bindgen(js_name = _C_FindObjectsFinal)]
pub fn C_FindObjectsFinal(h_session: u32) -> u32 {
    FIND_STATE.with(|s| {
        s.borrow_mut().remove(&h_session);
    });
    CKR_OK
}

// ── GenerateRandom ──────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateRandom)]
pub fn C_GenerateRandom(_h_session: u32, p_random_data: *mut u8, ul_random_len: u32) -> u32 {
    if p_random_data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let buf = std::slice::from_raw_parts_mut(p_random_data, ul_random_len as usize);
        match getrandom::getrandom(buf) {
            Ok(_) => CKR_OK,
            Err(_) => CKR_FUNCTION_FAILED,
        }
    }
}

// ── DeriveKey (ECDH, PBKDF2, HKDF, KBKDF) ──────────────────────────────────

#[wasm_bindgen(js_name = _C_DeriveKey)]
pub fn C_DeriveKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_base_key: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    ph_key: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        let key_len =
            get_attr_ulong(p_template, ul_attribute_count, CKA_VALUE_LEN).unwrap_or(32) as usize;

        // PKCS#11 v3.2 §5.18: for key-based derivation, verify CKA_DERIVE on the base key.
        // PBKDF2 uses h_base_key=0 (password in params), so skip the check for that case.
        if h_base_key != 0 {
            let can_derive = OBJECTS.with(|o| {
                o.borrow()
                    .get(&h_base_key)
                    .map(|attrs| read_bool_attr(attrs, CKA_DERIVE))
                    .unwrap_or(false)
            });
            if !can_derive {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        let key_value: Vec<u8> = match mech_type {
            // ── ECDH ────────────────────────────────────────────────────────
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => {
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_ECDH1_DERIVE_PARAMS: [kdf, ulSharedDataLen, pSharedData, ulPublicDataLen, pPublicData]
                let peer_pk_len = *p_param.add(3) as usize;
                let peer_pk_ptr = *p_param.add(4) as usize as *const u8;
                if peer_pk_ptr.is_null() || peer_pk_len == 0 {
                    return CKR_ARGUMENTS_BAD;
                }
                let peer_pk_bytes = std::slice::from_raw_parts(peer_pk_ptr, peer_pk_len);
                let our_sk_bytes = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let algo = get_object_algo_family(h_base_key);
                let curve = get_object_param_set(h_base_key);
                let shared = match (algo, curve) {
                    (ALGO_ECDSA, CURVE_P256) | (ALGO_ECDH_P256, _) | (0, CURVE_P256) => {
                        let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                            Ok(s) => s,
                            Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                        };
                        let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                            Ok(pk) => pk,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                            .raw_secret_bytes()
                            .to_vec()
                    }
                    (ALGO_ECDH_X25519, _) => {
                        if our_sk_bytes.len() != 32 || peer_pk_bytes.len() != 32 {
                            return CKR_KEY_TYPE_INCONSISTENT;
                        }
                        let mut sk_arr = [0u8; 32];
                        sk_arr.copy_from_slice(&our_sk_bytes);
                        let sk = x25519_dalek::StaticSecret::from(sk_arr);
                        let mut pk_arr = [0u8; 32];
                        pk_arr.copy_from_slice(peer_pk_bytes);
                        let result = sk
                            .diffie_hellman(&x25519_dalek::PublicKey::from(pk_arr))
                            .as_bytes()
                            .to_vec();
                        pk_arr.zeroize();
                        result
                    }
                    _ => {
                        if our_sk_bytes.len() == 32 && peer_pk_bytes.len() == 65 {
                            let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                                Ok(s) => s,
                                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                            };
                            let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                                Ok(pk) => pk,
                                Err(_) => return CKR_ARGUMENTS_BAD,
                            };
                            p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                                .raw_secret_bytes()
                                .to_vec()
                        } else {
                            return CKR_KEY_TYPE_INCONSISTENT;
                        }
                    }
                };
                if key_len <= shared.len() {
                    shared[..key_len].to_vec()
                } else {
                    shared
                }
            }

            // ── PBKDF2 ──────────────────────────────────────────────────────
            CKM_PKCS5_PBKD2 => {
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_PKCS5_PBKD2_PARAMS2: [saltSource, pSaltData, ulSaltDataLen, iterations, prf,
                //                           pPrfData, ulPrfDataLen, pPassword, ulPasswordLen]
                let salt_ptr = *p_param.add(1) as usize as *const u8;
                let salt_len = *p_param.add(2) as usize;
                let iterations = *p_param.add(3);
                if iterations < 1000 {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf = *p_param.add(4);
                let pass_ptr = *p_param.add(7) as usize as *const u8;
                let pass_len = *p_param.add(8) as usize;
                let salt = if !salt_ptr.is_null() && salt_len > 0 {
                    std::slice::from_raw_parts(salt_ptr, salt_len)
                } else {
                    &[]
                };
                let pass = if !pass_ptr.is_null() && pass_len > 0 {
                    std::slice::from_raw_parts(pass_ptr, pass_len)
                } else {
                    &[]
                };
                let mut out = vec![0u8; key_len];
                match prf {
                    CKP_PBKDF2_HMAC_SHA256 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, iterations, &mut out)
                    }
                    CKP_PBKDF2_HMAC_SHA384 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, salt, iterations, &mut out)
                    }
                    CKP_PBKDF2_HMAC_SHA512 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, salt, iterations, &mut out)
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                out
            }

            // ── HKDF ────────────────────────────────────────────────────────
            CKM_HKDF_DERIVE => {
                let ikm = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_HKDF_PARAMS: bExtract(b0), bExpand(b1), pad(b2-3), prf(4), saltType(8),
                //                  pSalt(12), ulSaltLen(16), hSaltKey(20), pInfo(24), ulInfoLen(28)
                let first_word = *p_param.add(0);
                let b_expand = ((first_word >> 8) & 0xFF) != 0;
                let prf = *p_param.add(1);
                let salt_type = *p_param.add(2);
                let salt_ptr = *p_param.add(3) as usize as *const u8;
                let salt_len = *p_param.add(4) as usize;
                let info_ptr = *p_param.add(6) as usize as *const u8;
                let info_len = *p_param.add(7) as usize;
                let salt_opt =
                    if salt_type == CKF_HKDF_SALT_DATA && !salt_ptr.is_null() && salt_len > 0 {
                        Some(std::slice::from_raw_parts(salt_ptr, salt_len))
                    } else {
                        None
                    };
                let info = if !info_ptr.is_null() && info_len > 0 {
                    std::slice::from_raw_parts(info_ptr, info_len)
                } else {
                    &[]
                };
                let mut out = vec![0u8; key_len];
                if b_expand {
                    match prf {
                        CKM_SHA384 => {
                            let hk = hkdf::Hkdf::<sha2::Sha384>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA512 => {
                            let hk = hkdf::Hkdf::<sha2::Sha512>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA3_256 => {
                            let hk = hkdf::Hkdf::<sha3::Sha3_256>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA3_512 => {
                            let hk = hkdf::Hkdf::<sha3::Sha3_512>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        _ => {
                            // CKM_SHA256 default
                            let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                    }
                } else {
                    // extract-only: write PRK to output using the requested PRF
                    macro_rules! hkdf_extract {
                        ($H:ty) => {{
                            let (prk, _) = hkdf::Hkdf::<$H>::extract(salt_opt, &ikm);
                            let copy_len = key_len.min(prk.len());
                            out[..copy_len].copy_from_slice(&prk[..copy_len]);
                        }};
                    }
                    match prf {
                        CKM_SHA384 => hkdf_extract!(sha2::Sha384),
                        CKM_SHA512 => hkdf_extract!(sha2::Sha512),
                        CKM_SHA3_256 => hkdf_extract!(sha3::Sha3_256),
                        CKM_SHA3_512 => hkdf_extract!(sha3::Sha3_512),
                        _ => hkdf_extract!(sha2::Sha256), // CKM_SHA256 default
                    }
                }
                out
            }

            // ── SP 800-108 Counter KBKDF ─────────────────────────────────────
            CKM_SP800_108_COUNTER_KDF => {
                use hmac::{Hmac, Mac};
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf_type = *p_param.add(0);
                let num_segs = *p_param.add(1) as usize;
                let p_segs = *p_param.add(2) as usize as *const u32;
                // Collect fixed input from BYTE_ARRAY segments
                let mut fixed: Vec<u8> = Vec::new();
                if !p_segs.is_null() {
                    for i in 0..num_segs {
                        let seg_type = *p_segs.add(i * 3);
                        if seg_type == CK_SP800_108_BYTE_ARRAY {
                            let val_ptr = *p_segs.add(i * 3 + 1) as usize as *const u8;
                            let val_len = *p_segs.add(i * 3 + 2) as usize;
                            if !val_ptr.is_null() && val_len > 0 {
                                fixed.extend_from_slice(std::slice::from_raw_parts(
                                    val_ptr, val_len,
                                ));
                            }
                        }
                    }
                }
                // K(i) = PRF(base_key, counter_be32 || fixed_input)
                macro_rules! kbkdf_counter {
                    ($HmacType:ty, $block_size:expr) => {{
                        let mut out = Vec::new();
                        let mut counter: u32 = 1;
                        while out.len() < key_len {
                            let mut mac = match <$HmacType>::new_from_slice(&base_key) {
                                Ok(m) => m,
                                Err(_) => return CKR_FUNCTION_FAILED,
                            };
                            mac.update(&counter.to_be_bytes());
                            mac.update(&fixed);
                            out.extend_from_slice(&mac.finalize().into_bytes());
                            counter += 1;
                        }
                        out.truncate(key_len);
                        out
                    }};
                }
                match prf_type {
                    CKM_SHA384 => kbkdf_counter!(Hmac<sha2::Sha384>, 48),
                    CKM_SHA512 => kbkdf_counter!(Hmac<sha2::Sha512>, 64),
                    CKM_SHA3_256 => kbkdf_counter!(Hmac<sha3::Sha3_256>, 32),
                    CKM_SHA3_512 => kbkdf_counter!(Hmac<sha3::Sha3_512>, 64),
                    _ => kbkdf_counter!(Hmac<sha2::Sha256>, 32), // SHA-256 default
                }
            }

            // ── SP 800-108 Feedback KBKDF ────────────────────────────────────
            CKM_SP800_108_FEEDBACK_KDF => {
                use hmac::{Hmac, Mac};
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf_type = *p_param.add(0);
                let num_segs = *p_param.add(1) as usize;
                let p_segs = *p_param.add(2) as usize as *const u32;
                let iv_len = *p_param.add(3) as usize;
                let iv_ptr = *p_param.add(4) as usize as *const u8;
                let iv = if !iv_ptr.is_null() && iv_len > 0 {
                    std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
                } else {
                    Vec::new()
                };
                let mut fixed: Vec<u8> = Vec::new();
                if !p_segs.is_null() {
                    for i in 0..num_segs {
                        let seg_type = *p_segs.add(i * 3);
                        if seg_type == CK_SP800_108_BYTE_ARRAY {
                            let val_ptr = *p_segs.add(i * 3 + 1) as usize as *const u8;
                            let val_len = *p_segs.add(i * 3 + 2) as usize;
                            if !val_ptr.is_null() && val_len > 0 {
                                fixed.extend_from_slice(std::slice::from_raw_parts(
                                    val_ptr, val_len,
                                ));
                            }
                        }
                    }
                }
                // K(i) = PRF(base_key, K(i-1) || fixed_input)
                macro_rules! kbkdf_feedback {
                    ($HmacType:ty) => {{
                        let mut k_prev = iv.clone();
                        let mut out = Vec::new();
                        while out.len() < key_len {
                            let mut mac = match <$HmacType>::new_from_slice(&base_key) {
                                Ok(m) => m,
                                Err(_) => return CKR_FUNCTION_FAILED,
                            };
                            mac.update(&k_prev);
                            mac.update(&fixed);
                            k_prev = mac.finalize().into_bytes().to_vec();
                            out.extend_from_slice(&k_prev);
                        }
                        out.truncate(key_len);
                        out
                    }};
                }
                match prf_type {
                    CKM_SHA384 => kbkdf_feedback!(Hmac<sha2::Sha384>),
                    CKM_SHA512 => kbkdf_feedback!(Hmac<sha2::Sha512>),
                    CKM_SHA3_256 => kbkdf_feedback!(Hmac<sha3::Sha3_256>),
                    CKM_SHA3_512 => kbkdf_feedback!(Hmac<sha3::Sha3_512>),
                    _ => kbkdf_feedback!(Hmac<sha2::Sha256>),
                }
            }

            _ => return CKR_MECHANISM_INVALID,
        };

        let mut attrs = HashMap::new();
        let vlen = key_value.len() as u32;
        attrs.insert(CKA_VALUE, key_value);
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        store_bool(&mut attrs, CKA_SENSITIVE, false);
        store_ulong(&mut attrs, CKA_VALUE_LEN, vlen);
        absorb_template_attrs(&mut attrs, p_template, ul_attribute_count);
        *ph_key = allocate_handle(attrs);
    }
    CKR_OK
}

// ── Key Wrap/Unwrap ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_WrapKey)]
pub fn C_WrapKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_wrapping_key: u32,
    h_key: u32,
    p_wrapped_key: *mut u8,
    pul_wrapped_key_len: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD_LEGACY;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        if !is_aes_wrap && !is_rsa_oaep {
            return CKR_MECHANISM_INVALID;
        }

        // Check CKA_WRAP on wrapping key
        let can_wrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_wrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_WRAP))
                .unwrap_or(false)
        });
        if !can_wrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        // Check CKA_EXTRACTABLE on target key
        let extractable = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_EXTRACTABLE))
                .unwrap_or(false)
        });
        if !extractable {
            return CKR_KEY_UNEXTRACTABLE;
        }

        let wrapping_key = match get_object_value(h_wrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let key_to_wrap = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };

        let wrapped = if is_rsa_oaep {
            // RSA-OAEP wrapping — encrypt key value with RSA public key
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            let hash_alg = if !p_param.is_null() && ul_param_len >= 4 {
                *(p_param as *const u32)
            } else {
                CKM_SHA256
            };
            if wrapping_key.len() < 8 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n_len = u32::from_le_bytes([
                wrapping_key[0],
                wrapping_key[1],
                wrapping_key[2],
                wrapping_key[3],
            ]) as usize;
            if wrapping_key.len() < 4 + n_len + 1 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n = rsa::BigUint::from_bytes_be(&wrapping_key[4..4 + n_len]);
            let e = rsa::BigUint::from_bytes_be(&wrapping_key[4 + n_len..]);
            let pk = match rsa::RsaPublicKey::new(n, e) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let mut rng = rand::rngs::OsRng;
            let oaep = match hash_alg {
                CKM_SHA384 => rsa::Oaep::new::<sha2::Sha384>(),
                CKM_SHA512 => rsa::Oaep::new::<sha2::Sha512>(),
                _ => rsa::Oaep::new::<sha2::Sha256>(),
            };
            match pk.encrypt(&mut rng, oaep, &key_to_wrap) {
                Ok(ct) => ct,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else if is_kwp {
            use aes::cipher::generic_array::GenericArray;
            // AES-KWP (RFC 5649) — supports arbitrary-length data
            if key_to_wrap.is_empty() {
                return CKR_DATA_INVALID;
            }
            let result = match wrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            match result {
                Ok(v) => v,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else {
            use aes::cipher::generic_array::GenericArray;
            // AES-KW (RFC 3394) — requires data to be multiple of 8 and >= 16
            if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
                return CKR_DATA_INVALID;
            }
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            let wrap_ok = match wrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            if !wrap_ok {
                return CKR_FUNCTION_FAILED;
            }
            buf
        };

        if p_wrapped_key.is_null() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_OK;
        }
        if (*pul_wrapped_key_len as usize) < wrapped.len() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(wrapped.as_ptr(), p_wrapped_key, wrapped.len());
        *pul_wrapped_key_len = wrapped.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_UnwrapKey)]
pub fn C_UnwrapKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_unwrapping_key: u32,
    p_wrapped_key: *mut u8,
    ul_wrapped_key_len: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    ph_key: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD_LEGACY;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        if !is_aes_wrap && !is_rsa_oaep {
            return CKR_MECHANISM_INVALID;
        }

        // Check CKA_UNWRAP on unwrapping key
        let can_unwrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_unwrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_UNWRAP))
                .unwrap_or(false)
        });
        if !can_unwrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        let unwrapping_key = match get_object_value(h_unwrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        let key_value = if is_rsa_oaep {
            // RSA-OAEP unwrapping — decrypt wrapped key with RSA private key
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            let hash_alg = if !p_param.is_null() && ul_param_len >= 4 {
                *(p_param as *const u32)
            } else {
                CKM_SHA256
            };
            use rsa::pkcs8::DecodePrivateKey;
            let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&unwrapping_key) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let oaep = match hash_alg {
                CKM_SHA384 => rsa::Oaep::new::<sha2::Sha384>(),
                CKM_SHA512 => rsa::Oaep::new::<sha2::Sha512>(),
                _ => rsa::Oaep::new::<sha2::Sha256>(),
            };
            match sk.decrypt(oaep, wrapped_data) {
                Ok(pt) => pt,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else if is_kwp {
            use aes::cipher::generic_array::GenericArray;
            // AES-KWP (RFC 5649) — supports arbitrary-length data
            if wrapped_data.len() < 16 {
                return CKR_ARGUMENTS_BAD;
            }
            let result = match unwrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            match result {
                Ok(v) => v,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else {
            use aes::cipher::generic_array::GenericArray;
            // AES-KW (RFC 3394)
            if wrapped_data.len() < 24 {
                return CKR_ARGUMENTS_BAD;
            }
            let mut buf = vec![0u8; wrapped_data.len() - 8];
            let unwrap_ok = match unwrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            if !unwrap_ok {
                return CKR_FUNCTION_FAILED;
            }
            buf
        };
        let key_len = key_value.len() as u32;

        // Parse template attributes (if provided)
        let mut attrs = HashMap::new();
        if !p_template.is_null() && ul_attribute_count > 0 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
                // Skip CKA_VALUE — it comes from the unwrap operation
                if attr_type == CKA_VALUE {
                    continue;
                }
                if !val_ptr.is_null() && val_len > 0 {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    attrs.insert(attr_type, v);
                }
            }
        }

        // Set key material from unwrap operation
        attrs.insert(CKA_VALUE, key_value);

        // Apply defaults for missing attributes
        if !attrs.contains_key(&CKA_CLASS) {
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        }
        if !attrs.contains_key(&CKA_KEY_TYPE) {
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        }
        if !attrs.contains_key(&CKA_VALUE_LEN) {
            store_ulong(&mut attrs, CKA_VALUE_LEN, key_len);
        }
        if !attrs.contains_key(&CKA_TOKEN) {
            store_bool(&mut attrs, CKA_TOKEN, false);
        }
        if !attrs.contains_key(&CKA_EXTRACTABLE) {
            store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        }
        if !attrs.contains_key(&CKA_SENSITIVE) {
            store_bool(&mut attrs, CKA_SENSITIVE, false);
        }

        // Handle CKA_PARAMETER_SET for PQC keys
        if let Some(ps_bytes) = attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut attrs, ps);
            }
        }

        *ph_key = allocate_handle(attrs);
    }
    CKR_OK
}

// ── Authenticated key wrapping (PKCS#11 v3.2 §5.18.6 / §5.18.7) ────────────
// C_WrapKeyAuthenticated wraps a key using an AEAD mechanism (AES-GCM).
// C_UnwrapKeyAuthenticated unwraps, creating a new key object.
// Signature follows pkcs11f.h exactly.

#[wasm_bindgen(js_name = _C_WrapKeyAuthenticated)]
pub fn C_WrapKeyAuthenticated(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_wrapping_key: u32,
    h_key: u32,
    _p_associated_data: *mut u8,
    _ul_associated_data_len: u32,
    p_wrapped_key: *mut u8,
    pul_wrapped_key_len: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);
        if p_param.is_null() || ul_param_len < 20 {
            return CKR_ARGUMENTS_BAD;
        }
        let gcm = p_param as *const u32;
        let iv_ptr = *gcm as usize as *const u8;
        let iv_len = *gcm.add(1) as usize;
        let iv = if !iv_ptr.is_null() && iv_len > 0 {
            if iv_len != 12 {
                return CKR_ARGUMENTS_BAD;
            }
            std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
        } else {
            vec![0u8; 12]
        };

        // Check CKA_WRAP on wrapping key
        let can_wrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_wrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_WRAP))
                .unwrap_or(false)
        });
        if !can_wrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        // Check CKA_EXTRACTABLE on target key
        let extractable = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_EXTRACTABLE))
                .unwrap_or(false)
        });
        if !extractable {
            return CKR_KEY_UNEXTRACTABLE;
        }

        let wrapping_key = match get_object_value(h_wrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let key_to_wrap = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };

        // AES-GCM encrypt
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
        let nonce = GenericArray::from_slice(&iv);
        let wrapped = match wrapping_key.len() {
            16 => Aes128Gcm::new_from_slice(&wrapping_key)
                .unwrap()
                .encrypt(nonce, key_to_wrap.as_slice()),
            32 => Aes256Gcm::new_from_slice(&wrapping_key)
                .unwrap()
                .encrypt(nonce, key_to_wrap.as_slice()),
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let wrapped = match wrapped {
            Ok(ct) => ct,
            Err(_) => return CKR_FUNCTION_FAILED,
        };

        // Length query or copy
        if p_wrapped_key.is_null() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_OK;
        }
        if (*pul_wrapped_key_len as usize) < wrapped.len() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(wrapped.as_ptr(), p_wrapped_key, wrapped.len());
        *pul_wrapped_key_len = wrapped.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_UnwrapKeyAuthenticated)]
pub fn C_UnwrapKeyAuthenticated(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_unwrapping_key: u32,
    p_wrapped_key: *mut u8,
    ul_wrapped_key_len: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    _p_associated_data: *mut u8,
    _ul_associated_data_len: u32,
    ph_key: *mut u32,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);
        if p_param.is_null() || ul_param_len < 20 {
            return CKR_ARGUMENTS_BAD;
        }
        let gcm = p_param as *const u32;
        let iv_ptr = *gcm as usize as *const u8;
        let iv_len = *gcm.add(1) as usize;
        let iv = if !iv_ptr.is_null() && iv_len > 0 {
            if iv_len != 12 {
                return CKR_ARGUMENTS_BAD;
            }
            std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
        } else {
            vec![0u8; 12]
        };

        // Check CKA_UNWRAP on unwrapping key
        let can_unwrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_unwrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_UNWRAP))
                .unwrap_or(false)
        });
        if !can_unwrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        let unwrapping_key = match get_object_value(h_unwrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        // AES-GCM decrypt
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
        let nonce = GenericArray::from_slice(&iv);
        let key_value = match unwrapping_key.len() {
            16 => Aes128Gcm::new_from_slice(&unwrapping_key)
                .unwrap()
                .decrypt(nonce, wrapped_data),
            32 => Aes256Gcm::new_from_slice(&unwrapping_key)
                .unwrap()
                .decrypt(nonce, wrapped_data),
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let key_value = match key_value {
            Ok(pt) => pt,
            Err(_) => return CKR_FUNCTION_FAILED,
        };
        let key_len = key_value.len() as u32;

        // Parse template attributes (same as C_UnwrapKey)
        let mut attrs = HashMap::new();
        if !p_template.is_null() && ul_attribute_count > 0 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
                if attr_type == CKA_VALUE {
                    continue;
                }
                if !val_ptr.is_null() && val_len > 0 {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    attrs.insert(attr_type, v);
                }
            }
        }

        // Set key material from unwrap operation
        attrs.insert(CKA_VALUE, key_value);

        // Apply defaults for missing attributes
        if !attrs.contains_key(&CKA_CLASS) {
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        }
        if !attrs.contains_key(&CKA_KEY_TYPE) {
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        }
        if !attrs.contains_key(&CKA_VALUE_LEN) {
            store_ulong(&mut attrs, CKA_VALUE_LEN, key_len);
        }
        if !attrs.contains_key(&CKA_TOKEN) {
            store_bool(&mut attrs, CKA_TOKEN, false);
        }
        if !attrs.contains_key(&CKA_EXTRACTABLE) {
            store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        }
        if !attrs.contains_key(&CKA_SENSITIVE) {
            store_bool(&mut attrs, CKA_SENSITIVE, false);
        }

        if let Some(ps_bytes) = attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut attrs, ps);
            }
        }

        *ph_key = allocate_handle(attrs);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_SignUpdate)]
pub fn C_SignUpdate(_h_session: u32, _p_part: *mut u8, _ul_part_len: u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SignFinal)]
pub fn C_SignFinal(_h_session: u32, _p_signature: *mut u8, _pul_signature_len: *mut u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_VerifyUpdate)]
pub fn C_VerifyUpdate(_h_session: u32, _p_part: *mut u8, _ul_part_len: u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_VerifyFinal)]
pub fn C_VerifyFinal(_h_session: u32, _p_signature: *mut u8, _ul_signature_len: u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_EncryptUpdate)]
pub fn C_EncryptUpdate(
    _h_session: u32,
    _p_part: *mut u8,
    _ul_part_len: u32,
    _p_encrypted_part: *mut u8,
    _pul_encrypted_part_len: *mut u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_EncryptFinal)]
pub fn C_EncryptFinal(
    _h_session: u32,
    _p_last_encrypted_part: *mut u8,
    _pul_last_encrypted_part_len: *mut u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_DecryptUpdate)]
pub fn C_DecryptUpdate(
    _h_session: u32,
    _p_encrypted_part: *mut u8,
    _ul_encrypted_part_len: u32,
    _p_part: *mut u8,
    _pul_part_len: *mut u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_DecryptFinal)]
pub fn C_DecryptFinal(_h_session: u32, _p_last_part: *mut u8, _pul_last_part_len: *mut u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

// ── Stubs for optional PKCS#11 v3.2 admin/management functions ───────────────
//
// These functions are not required for cryptographic operations but must exist
// in a compliant library. All return CKR_FUNCTION_NOT_SUPPORTED per PKCS#11 v3.2 §11.17.
// Exceptions: C_GetInfo and C_GetSlotInfo are implemented with basic data.

/// CK_INFO: cryptokiVersion(2) + manufacturerID(32) + flags(4) + libraryDescription(32) + libraryVersion(2) = 72 bytes
#[wasm_bindgen(js_name = _C_GetInfo)]
pub fn C_GetInfo(p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let info = std::slice::from_raw_parts_mut(p_info, 72);
        info.fill(0);
        // cryptokiVersion: major=3, minor=2
        info[0] = 3;
        info[1] = 2;
        // manufacturerID[32]: "SoftHSMv3 Rust WASM            " (padded with spaces)
        let mfr = b"SoftHSMv3 Rust WASM             ";
        info[2..34].copy_from_slice(&mfr[..32]);
        // flags (4 bytes at offset 34): 0
        // libraryDescription[32] at offset 38
        let desc = b"PQC PKCS#11 v3.2 Rust WASM      ";
        info[38..70].copy_from_slice(&desc[..32]);
        // libraryVersion at offset 70: major=3, minor=0
        info[70] = 3;
        info[71] = 0;
    }
    CKR_OK
}

/// C_GetSlotInfo: returns basic slot info for slot 0.
/// CK_SLOT_INFO: slotDescription(64) + manufacturerID(32) + flags(4) + hardwareVersion(2) + firmwareVersion(2) = 104 bytes
#[wasm_bindgen(js_name = _C_GetSlotInfo)]
pub fn C_GetSlotInfo(_slot_id: u32, p_info: *mut u8) -> u32 {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let info = std::slice::from_raw_parts_mut(p_info, 104);
        info.fill(b' '); // PKCS#11 padding is spaces for char arrays
                         // slotDescription[64] at offset 0
        let desc = b"SoftHSMv3 Rust WASM Virtual Slot                                ";
        info[0..64].copy_from_slice(&desc[..64]);
        // manufacturerID[32] at offset 64
        let mfr = b"SoftHSMv3 Rust WASM             ";
        info[64..96].copy_from_slice(&mfr[..32]);
        // flags (4 bytes at offset 96): CKF_TOKEN_PRESENT(1) | CKF_HW_SLOT(0) = 0x01
        info[96] = 0x01;
        info[97] = 0x00;
        info[98] = 0x00;
        info[99] = 0x00;
        // hardwareVersion at offset 100: {1, 0}
        info[100] = 1;
        info[101] = 0;
        // firmwareVersion at offset 102: {3, 0}
        info[102] = 3;
        info[103] = 0;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_SetPIN)]
pub fn C_SetPIN(
    _h_session: u32,
    _p_old_pin: *mut u8,
    _ul_old_len: u32,
    _p_new_pin: *mut u8,
    _ul_new_len: u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_CopyObject)]
pub fn C_CopyObject(
    _h_session: u32,
    _h_object: u32,
    _p_template: *mut u8,
    _ul_count: u32,
    _ph_new_object: *mut u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_GetObjectSize)]
pub fn C_GetObjectSize(_h_session: u32, _h_object: u32, _pul_size: *mut u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SetAttributeValue)]
pub fn C_SetAttributeValue(
    _h_session: u32,
    _h_object: u32,
    _p_template: *mut u8,
    _ul_count: u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_DigestKey)]
pub fn C_DigestKey(_h_session: u32, _h_key: u32) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_GetOperationState)]
pub fn C_GetOperationState(
    _h_session: u32,
    _p_operation_state: *mut u8,
    _pul_operation_state_len: *mut u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SetOperationState)]
pub fn C_SetOperationState(
    _h_session: u32,
    _p_operation_state: *mut u8,
    _ul_operation_state_len: u32,
    _h_encryption_key: u32,
    _h_authentication_key: u32,
) -> u32 {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SeedRandom)]
pub fn C_SeedRandom(_h_session: u32, _p_seed: *mut u8, _ul_seed_len: u32) -> u32 {
    // WASM getrandom is OS-backed; external seeding is not supported
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen]
pub struct SoftHsmRust {}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: u32,
    pub pParameter: *mut u8,
    pub ulParameterLen: u32,
}

impl Default for SoftHsmRust {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl SoftHsmRust {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SoftHsmRust {
        // Initialize underlying WASM runtime hooks if needed
        C_Initialize(std::ptr::null_mut());
        SoftHsmRust {}
    }

    pub fn init_token(&self, slot_id: u32, pin: &str, label: &str) -> bool {
        // Just a mock pass for tests
        let mut p_pin = pin.as_bytes().to_vec();
        let mut p_label = label.as_bytes().to_vec();
        p_label.resize(32, b' ');

        let result = C_InitToken(
            slot_id,
            p_pin.as_mut_ptr(),
            p_pin.len() as u32,
            p_label.as_mut_ptr(),
        );
        result == CKR_OK
    }

    pub fn generate_aes_key(&self, key_size: u32) -> u32 {
        let mut h_session: u32 = 0;
        C_OpenSession(
            0,
            6,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut h_session,
        );

        // Mock template for AES key
        let mut h_key: u32 = 0;
        let ck_true = 1u8;
        let k_type = CKK_AES;
        let class = CKO_SECRET_KEY;
        let val_len = key_size;

        let mut tmpl = vec![
            CKA_CLASS,
            &class as *const _ as u32,
            4,
            CKA_KEY_TYPE,
            &k_type as *const _ as u32,
            4,
            CKA_VALUE_LEN,
            &val_len as *const _ as u32,
            4,
            CKA_ENCRYPT,
            &ck_true as *const _ as u32,
            1,
            CKA_DECRYPT,
            &ck_true as *const _ as u32,
            1,
        ];

        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        C_GenerateKey(
            h_session,
            &mut mech as *mut _ as *mut u8,
            tmpl.as_mut_ptr() as *mut u8,
            5,
            &mut h_key,
        );
        h_key
    }

    pub fn aes_ctr_encrypt(
        &self,
        key_handle: u32,
        iv: &[u8],
        plaintext: &[u8],
    ) -> js_sys::Uint8Array {
        let mut param = vec![0u8; 20];
        param[0..4].copy_from_slice(&128u32.to_ne_bytes());
        param[4..20].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: 20,
        };

        // Use a mock session 1 since it's just tests
        let h_session = 1;
        C_EncryptInit(h_session, &mut mech as *mut _ as *mut u8, key_handle);

        let mut out_len = plaintext.len() as u32;
        let mut out = vec![0u8; plaintext.len()];

        C_Encrypt(
            h_session,
            plaintext.as_ptr() as *mut u8,
            plaintext.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        );

        js_sys::Uint8Array::from(&out[..out_len as usize])
    }

    pub fn aes_ctr_decrypt(
        &self,
        key_handle: u32,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> js_sys::Uint8Array {
        let mut param = vec![0u8; 20];
        param[0..4].copy_from_slice(&128u32.to_ne_bytes());
        param[4..20].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: 20,
        };

        let h_session = 1;
        C_DecryptInit(h_session, &mut mech as *mut _ as *mut u8, key_handle);

        let mut out_len = ciphertext.len() as u32;
        let mut out = vec![0u8; ciphertext.len()];

        C_Decrypt(
            h_session,
            ciphertext.as_ptr() as *mut u8,
            ciphertext.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        );

        js_sys::Uint8Array::from(&out[..out_len as usize])
    }
}
