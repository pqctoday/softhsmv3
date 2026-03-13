with open("src/state.rs", "r") as f:
    text = f.read()

text = text.replace("    static OBJECTS:",    "    pub static OBJECTS:")
text = text.replace("    static NEXT_HANDLE:", "    pub static NEXT_HANDLE:")
text = text.replace("    static SIGN_STATE:",  "    pub static SIGN_STATE:")
text = text.replace("    static VERIFY_STATE:", "    pub static VERIFY_STATE:")
text = text.replace("    static ENCRYPT_STATE:", "    pub static ENCRYPT_STATE:")
text = text.replace("    static DECRYPT_STATE:", "    pub static DECRYPT_STATE:")
text = text.replace("    static DIGEST_STATE:", "    pub static DIGEST_STATE:")
text = text.replace("    static FIND_STATE:",   "    pub static FIND_STATE:")
text = text.replace("    static ALLOC_SIZES:",  "    pub static ALLOC_SIZES:")

text = text.replace("struct EncryptCtx {",    "pub struct EncryptCtx {")
text = text.replace("    mech_type: u32,",     "    pub mech_type: u32,")
text = text.replace("    key_handle: u32,",    "    pub key_handle: u32,")
text = text.replace("    iv: Vec<u8>,",        "    pub iv: Vec<u8>,")
text = text.replace("    aad: Vec<u8>,",       "    pub aad: Vec<u8>,")
text = text.replace("    tag_bits: u32,",      "    pub tag_bits: u32,")

text = text.replace("\nfn allocate_handle",   "\npub fn allocate_handle")
text = text.replace("\nfn get_object_value",  "\npub fn get_object_value")
text = text.replace("\nfn get_object_param_set", "\npub fn get_object_param_set")
text = text.replace("\nfn get_object_algo_family", "\npub fn get_object_algo_family")
text = text.replace("\nfn store_param_set", "\npub fn store_param_set")
text = text.replace("\nfn store_algo_family", "\npub fn store_algo_family")
text = text.replace("\nfn store_bool", "\npub fn store_bool")
text = text.replace("\nfn store_ulong", "\npub fn store_ulong")
text = text.replace("\nfn read_bool_attr", "\npub fn read_bool_attr")
text = text.replace("\nfn finalize_private_key_attrs", "\npub fn finalize_private_key_attrs")

with open("src/state.rs", "w") as f:
    f.write(text)
