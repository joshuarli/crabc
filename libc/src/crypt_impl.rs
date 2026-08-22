// The deliberately small password-hash compatibility boundary.
//
// `crabc` does not implement cryptographic primitives or password-hash
// serialization. SHA-256-crypt and SHA-512-crypt are delegated to
// RustCrypto's `sha-crypt` MCF implementation. This file only validates the
// bounded C setting, copies the dependency-owned result into the caller's
// storage, and retains ABI-visible unsupported markers for algorithms outside
// the project profile.

extern crate alloc;

use base64ct::{Base64ShaCrypt, Encoding};
use core::alloc::{GlobalAlloc, Layout};
use sha_crypt::{Algorithm, Params, PasswordHasher, ShaCrypt};

const CRYPT_OUTPUT_MAX: usize = 256;

// `sha-crypt`'s MCF API owns its temporary `PasswordHash` string. Use the
// allocator already selected for the C ABI rather than introducing another
// allocator or a crypto-specific heap strategy.
struct CrabcRustAllocator;

unsafe impl GlobalAlloc for CrabcRustAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        libmimalloc_sys::mi_malloc_aligned(layout.size().max(1), layout.align()) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        libmimalloc_sys::mi_free(ptr as *mut crate::c_void)
    }
}

#[global_allocator]
static CRABC_RUST_ALLOCATOR: CrabcRustAllocator = CrabcRustAllocator;

#[repr(C)]
struct CryptData {
    initialized: c_int,
    buffer: [u8; CRYPT_OUTPUT_MAX],
}

unsafe fn cstr_bytes(s: *const c_char) -> &'static [u8] {
    if s.is_null() {
        return &[];
    }
    let len = strlen(s as *const c_char);
    core::slice::from_raw_parts(s as *const u8, len)
}

fn unsupported(output: *mut c_char) -> *mut c_char {
    if output.is_null() {
        return output;
    }
    unsafe {
        *output = b'*' as c_char;
        *output.add(1) = 0;
    }
    output
}

/// Bounded caller setting understood by the RustCrypto SHA-crypt adapter.
///
/// The setting is parsed only far enough to identify the algorithm, enforce
/// the bounded rounds field, and require the dependency's canonical
/// crypt-base64 salt. The dependency owns all password-hash computation and
/// MCF serialization. Empty and non-canonical salts are deliberately outside
/// this dependency-backed profile.
struct ShaSetting<'a> {
    algorithm: Algorithm,
    salt: &'a [u8],
    params: Params,
}

fn parse_sha_setting<'a>(setting: &'a [u8]) -> Option<ShaSetting<'a>> {
    let algorithm = match setting.get(..3)? {
        b"$5$" => Algorithm::Sha256Crypt,
        b"$6$" => Algorithm::Sha512Crypt,
        _ => return None,
    };

    let mut cursor = 3usize;
    let mut rounds = Params::RECOMMENDED_ROUNDS;
    if setting.get(cursor..cursor + 7) == Some(b"rounds=") {
        cursor += 7;
        let start = cursor;
        let mut parsed = 0u32;
        while let Some(&digit) = setting.get(cursor) {
            if !digit.is_ascii_digit() {
                break;
            }
            parsed = parsed.checked_mul(10)?.checked_add((digit - b'0') as u32)?;
            cursor += 1;
        }
        if cursor == start || setting.get(cursor) != Some(&b'$') {
            return None;
        }
        cursor += 1;
        rounds = parsed.max(Params::ROUNDS_MIN);
        if rounds > Params::ROUNDS_MAX {
            return None;
        }
    }

    let salt_start = cursor;
    while let Some(&byte) = setting.get(cursor) {
        if byte == b'$' || byte == 0 {
            break;
        }
        if byte == b'\n' || byte == b':' {
            return None;
        }
        cursor += 1;
        if cursor - salt_start == 16 {
            break;
        }
    }
    let salt = setting.get(salt_start..cursor)?;
    if salt.is_empty() || cursor != setting.len() {
        return None;
    }

    // Validate the bounded C setting without allocating. Decode again in the
    // hashing call into a stack buffer because the parsed view is borrowed
    // from the caller's setting string.
    let mut decoded = [0u8; 16];
    let decoded = Base64ShaCrypt::decode(salt, &mut decoded).ok()?;
    let mut canonical = [0u8; 24];
    let encoded = Base64ShaCrypt::encode(decoded, &mut canonical).ok()?;
    if encoded.as_bytes() != salt {
        return None;
    }
    let params = Params::new(rounds).ok()?;

    Some(ShaSetting {
        algorithm,
        salt,
        params,
    })
}

fn hash_sha(
    key: &[u8],
    setting: &[u8],
    output: &mut [u8; CRYPT_OUTPUT_MAX],
) -> Option<usize> {
    let parsed = parse_sha_setting(setting)?;
    let mut decoded_salt = [0u8; 16];
    let decoded_salt = Base64ShaCrypt::decode(parsed.salt, &mut decoded_salt).ok()?;
    let hasher = ShaCrypt::new(parsed.algorithm, parsed.params);
    let hash = hasher.hash_password_with_salt(key, decoded_salt).ok()?;
    let hash = hash.as_str().as_bytes();
    if hash.len() >= output.len() {
        return None;
    }
    output[..hash.len()].copy_from_slice(hash);
    Some(hash.len())
}

unsafe fn write_sha(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    if output.is_null() || setting.is_null() {
        return output;
    }
    let key = cstr_bytes(key);
    if key.len() > 256 {
        return unsupported(output);
    }
    let setting = cstr_bytes(setting);
    let mut result = [0u8; CRYPT_OUTPUT_MAX];
    let Some(length) = hash_sha(key, setting, &mut result) else {
        return unsupported(output);
    };
    let destination = core::slice::from_raw_parts_mut(output as *mut u8, length + 1);
    destination[..length].copy_from_slice(&result[..length]);
    destination[length] = 0;
    output
}

/// ABI-compatible helper retained for linkers; MD5-crypt is outside this
/// project's cryptography profile.
#[no_mangle]
pub unsafe extern "C" fn __crypt_md5(
    _key: *const c_char,
    _setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    unsupported(output)
}

/// ABI-compatible SHA-256-crypt helper backed by RustCrypto's `sha-crypt`.
#[no_mangle]
pub unsafe extern "C" fn __crypt_sha256(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    write_sha(key, setting, output)
}

/// ABI-compatible SHA-512-crypt helper backed by RustCrypto's `sha-crypt`.
#[no_mangle]
pub unsafe extern "C" fn __crypt_sha512(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    write_sha(key, setting, output)
}

/// ABI-compatible bcrypt helper; bcrypt is outside this project's profile.
#[no_mangle]
pub unsafe extern "C" fn __crypt_blowfish(
    _key: *const c_char,
    _setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    unsupported(output)
}

/// Dispatch supported SHA-crypt formats and retain historical helper symbols.
#[no_mangle]
pub unsafe extern "C" fn __crypt_r(
    key: *const c_char,
    setting: *const c_char,
    data: *mut crate::c_void,
) -> *mut c_char {
    if data.is_null() {
        return data as *mut c_char;
    }
    let output = (*(data as *mut CryptData)).buffer.as_mut_ptr() as *mut c_char;
    let setting_bytes = cstr_bytes(setting);
    match setting_bytes.get(0..3) {
        Some(b"$5$") => __crypt_sha256(key, setting, output),
        Some(b"$6$") => __crypt_sha512(key, setting, output),
        _ => unsupported(output),
    }
}

static mut CRYPT_DATA: CryptData = CryptData {
    initialized: 0,
    buffer: [0; CRYPT_OUTPUT_MAX],
};

#[no_mangle]
pub unsafe extern "C" fn crypt(key: *const c_char, setting: *const c_char) -> *mut c_char {
    __crypt_r(
        key,
        setting,
        core::ptr::addr_of_mut!(CRYPT_DATA) as *mut crate::c_void,
    )
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn crypt_r(
    key: *const c_char,
    setting: *const c_char,
    data: *mut crate::c_void,
) -> *mut c_char {
    __crypt_r(key, setting, data)
}
