// The historical `setkey`/`encrypt` ABI remains link-compatible, but its DES
// algorithm is deliberately unavailable. SCOPE.md forbids a local cipher
// implementation, and this legacy interface has no useful modern Rust
// contract. Keep the void symbols as inert compatibility machinery until a
// focused RustCrypto-backed design is justified.

#[no_mangle]
pub unsafe extern "C" fn setkey(_key: *const c_char) {}

#[no_mangle]
pub unsafe extern "C" fn encrypt(_block: *mut c_char, _edflag: c_int) {}
