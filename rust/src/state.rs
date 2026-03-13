use std::collections::HashMap;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

use crate::constants::*;
use crate::crypto::*;

thread_local! {
    pub static OBJECTS: RefCell<HashMap<u32, Attributes>> = RefCell::new(HashMap::new());
    pub static NEXT_HANDLE: RefCell<u32> = const { RefCell::new(100) };
    pub static SIGN_STATE: RefCell<HashMap<u32, (u32, u32)>> = RefCell::new(HashMap::new());
    pub static VERIFY_STATE: RefCell<HashMap<u32, (u32, u32)>> = RefCell::new(HashMap::new());
    pub static ENCRYPT_STATE: RefCell<HashMap<u32, EncryptCtx>> = RefCell::new(HashMap::new());
    pub static DECRYPT_STATE: RefCell<HashMap<u32, EncryptCtx>> = RefCell::new(HashMap::new());
    pub static DIGEST_STATE: RefCell<HashMap<u32, DigestCtx>> = RefCell::new(HashMap::new());
    pub static FIND_STATE: RefCell<HashMap<u32, FindCtx>> = RefCell::new(HashMap::new());
}

pub struct EncryptCtx {
    pub mech_type: u32,
    pub key_handle: u32,
    pub iv: Vec<u8>,
    #[allow(dead_code)]
    pub aad: Vec<u8>,
    #[allow(dead_code)]
    pub tag_bits: u32,
}

pub fn allocate_handle(attrs: Attributes) -> u32 {
    NEXT_HANDLE.with(|h| {
        let mut handle = h.borrow_mut();
        if *handle == u32::MAX {
            // Saturate at MAX rather than wrapping; callers get 0 as sentinel for failure.
            return 0;
        }
        let current = *handle;
        *handle += 1;
        OBJECTS.with(|objs| {
            objs.borrow_mut().insert(current, attrs);
        });
        current
    })
}

pub fn get_object_value(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_VALUE).cloned())
    })
}

pub fn get_object_param_set(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_PARAM_SET))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

pub fn get_object_algo_family(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_ALGO_FAMILY))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

/// Store parameter set as a 4-byte LE value in the attributes map.
pub fn store_param_set(attrs: &mut Attributes, ps: u32) {
    attrs.insert(CKA_PRIV_PARAM_SET, ps.to_le_bytes().to_vec());
}

/// Store algorithm family identifier in the attributes map.
pub fn store_algo_family(attrs: &mut Attributes, algo: u32) {
    attrs.insert(CKA_PRIV_ALGO_FAMILY, algo.to_le_bytes().to_vec());
}

/// Store a CK_BBOOL attribute (1 byte: 0x01 = true, 0x00 = false).
pub fn store_bool(attrs: &mut Attributes, attr_type: u32, value: bool) {
    attrs.insert(attr_type, vec![if value { 0x01 } else { 0x00 }]);
}

/// Store a CK_ULONG attribute (4-byte little-endian).
pub fn store_ulong(attrs: &mut Attributes, attr_type: u32, value: u32) {
    attrs.insert(attr_type, value.to_le_bytes().to_vec());
}

/// Read a CK_BBOOL attribute back from an attrs HashMap (returns false if absent).
pub fn read_bool_attr(attrs: &Attributes, attr_type: u32) -> bool {
    attrs
        .get(&attr_type)
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(false)
}

/// Derive and store CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE from the
/// final post-absorb values of CKA_SENSITIVE and CKA_EXTRACTABLE.
/// Must be called AFTER absorb_template_attrs so caller overrides are reflected.
pub fn finalize_private_key_attrs(attrs: &mut Attributes) {
    let sensitive = read_bool_attr(attrs, CKA_SENSITIVE);
    let extractable = read_bool_attr(attrs, CKA_EXTRACTABLE);
    store_bool(attrs, CKA_ALWAYS_SENSITIVE, sensitive);
    store_bool(attrs, CKA_NEVER_EXTRACTABLE, !extractable);
}

// ── Memory Management ────────────────────────────────────────────────────────

// ── Allocation size tracker ───────────────────────────────────────────────────
// Maps each live allocation pointer (as u32) → original size so that
// _free can reconstruct the exact Layout required by std::alloc::dealloc.
thread_local! {
    pub static ALLOC_SIZES: RefCell<HashMap<u32, u32>> = RefCell::new(HashMap::new());
}

#[wasm_bindgen(js_name = _malloc)]
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        // Return a stable non-null sentinel; caller must not dereference it.
        // We use address 4 (within the WASM reserved zero-page, never allocated).
        return 4 as *mut u8;
    }
    unsafe {
        let layout = std::alloc::Layout::from_size_align_unchecked(size, 1);
        let ptr = std::alloc::alloc(layout);
        if !ptr.is_null() {
            ALLOC_SIZES.with(|m| m.borrow_mut().insert(ptr as u32, size as u32));
        }
        ptr
    }
}

#[wasm_bindgen(js_name = _free)]
pub fn free(ptr: *mut u8, _js_size: usize) {
    if ptr.is_null() {
        return;
    }
    let addr = ptr as u32;
    if addr <= 8 {
        // sentinel or reserved-page pointer — nothing to deallocate
        return;
    }
    if let Some(size) = ALLOC_SIZES.with(|m| m.borrow_mut().remove(&addr)) {
        if size > 0 {
            unsafe {
                let layout = std::alloc::Layout::from_size_align_unchecked(size as usize, 1);
                std::alloc::dealloc(ptr, layout);
            }
        }
    }
    // If addr not in ALLOC_SIZES, it was never allocated through our _malloc
    // (e.g. a wasm-bindgen internal pointer). Silently ignore.
}
