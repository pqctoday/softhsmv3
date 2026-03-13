//! AES (GCM/CBC/KeyWrap), SHA/HMAC, and session management.

#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

pub mod constants;
pub mod crypto;
pub mod ffi;
pub mod state;

pub use ffi::*;
