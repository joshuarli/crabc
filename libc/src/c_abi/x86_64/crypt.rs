//! Bounded Linux/x86-64 C `crypt(3)` compatibility leaf.
//!
//! This is the target-local composition of the existing AArch64 profile, not
//! a new password-hash design. RustCrypto's `sha-crypt` owns SHA-256-crypt and
//! SHA-512-crypt computation and MCF serialization; `base64ct` validates the
//! caller setting. This module only performs bounded C ABI translation and
//! copies a dependency-owned result into C-owned output storage.
//!
//! The enabled `alloc` MCF serializer reaches only the final link's C
//! `malloc`/`aligned_alloc`/`free` boundary through a local global allocator
//! bridge. `x86-crypt` does not enable `x86-allocator-runtime` or select an
//! allocator backend; its static evidence deliberately supplies those three
//! symbols from pinned musl. That private implementation detail does not
//! select allocator lifecycle integration, dynamic runtime support, or public
//! x86 support.
//!
//! Source/provenance mapping is recorded in
//! `compat/x86_64/crypt-profile.md`. The behavior intentionally matches the
//! existing `libc/src/crypt_impl.rs` bounded profile, including its explicit
//! unsupported legacy `*` marker.

extern crate alloc;

use base64ct::{Base64ShaCrypt, Encoding};
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_int, c_void};
use sha_crypt::{Algorithm, Params, PasswordHasher, ShaCrypt};

const CRYPT_OUTPUT_MAX: usize = 256;
const CRYPT_KEY_MAX: usize = 256;
// `$5$`/`$6$`, optional `rounds=` plus a u32-width decimal field and `$`, and
// the profile's at-most-16-byte salt. No accepted setting can exceed this.
const CRYPT_SETTING_MAX: usize = 3 + 7 + 10 + 1 + 16;

struct CrabcRustAllocator;

unsafe extern "C" {
    #[link_name = "malloc"]
    fn cabi_malloc(size: usize) -> *mut c_void;
    #[link_name = "aligned_alloc"]
    fn cabi_aligned_alloc(alignment: usize, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_free(pointer: *mut c_void);
}

unsafe impl GlobalAlloc for CrabcRustAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        if layout.align() <= 16 {
            // SAFETY: the selected linked C allocator owns ordinary ABI
            // allocation; RustCrypto releases this result through `free`.
            return unsafe { cabi_malloc(size).cast::<u8>() };
        }
        let Some(rounded_size) = size.checked_add(layout.align() - 1).map(|value| value & !(layout.align() - 1)) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `Layout` supplies a power-of-two alignment and the rounded
        // nonzero size is its required multiple for C `aligned_alloc`.
        unsafe { cabi_aligned_alloc(layout.align(), rounded_size).cast::<u8>() }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        // SAFETY: `pointer` originated from the paired linked C allocation.
        unsafe { cabi_free(pointer.cast::<c_void>()) };
    }
}

#[global_allocator]
static CRABC_RUST_ALLOCATOR: CrabcRustAllocator = CrabcRustAllocator;

#[repr(C)]
struct CryptData {
    initialized: c_int,
    buffer: [u8; CRYPT_OUTPUT_MAX],
}

// `struct crypt_data` is a 260-byte C record: a four-byte `initialized` field
// followed by the 256-byte `__buf` result region. The result region is not a
// standalone 260-byte buffer.
const CRYPT_DATA_BYTES: usize = core::mem::size_of::<CryptData>();
const _: () = assert!(CRYPT_DATA_BYTES == 260);
const _: () = assert!(core::mem::align_of::<CryptData>() == core::mem::align_of::<c_int>());
const _: () = assert!(core::mem::offset_of!(CryptData, initialized) == 0);
const _: () = assert!(core::mem::offset_of!(CryptData, buffer) == core::mem::size_of::<c_int>());

/// Find a bounded caller C-string length without the wider x86 string runtime.
///
/// # Safety
///
/// When non-null, `value` must designate a readable NUL-terminated byte string
/// for at least `max_length + 1` bytes or through its terminator, whichever
/// comes first. A terminator beyond `max_length` returns `None` without an
/// unbounded scan.
unsafe fn cstr_length_bounded(value: *const c_char, max_length: usize) -> Option<usize> {
    if value.is_null() {
        return Some(0);
    }
    for length in 0..=max_length {
        // SAFETY: the C ABI caller retains the readable C-string obligation.
        if unsafe { value.cast::<u8>().add(length).read() } == 0 {
            return Some(length);
        }
    }
    None
}

/// Test a short literal prefix without scanning the rest of a caller string.
///
/// # Safety
///
/// When non-null, `value` must designate a readable NUL-terminated C string.
/// The loop stops at the first mismatch, including an early terminator.
unsafe fn cstr_starts_with(value: *const c_char, prefix: &[u8]) -> bool {
    if value.is_null() {
        return false;
    }
    for (offset, expected) in prefix.iter().enumerate() {
        // SAFETY: before the NUL terminator, C's string contract supplies the
        // next readable byte; an early terminator is a nonmatching byte.
        if unsafe { value.cast::<u8>().add(offset).read() } != *expected {
            return false;
        }
    }
    true
}

fn unsupported(output: *mut c_char) -> *mut c_char {
    if output.is_null() {
        return output;
    }
    // SAFETY: the public reentrant path supplies `crypt_data::__buf`; private
    // helper callers provide storage sufficient for this two-byte marker.
    unsafe {
        output.write(b'*' as c_char);
        output.add(1).write(0);
    }
    output
}

/// Borrowed, validated SHA-crypt C setting understood by the RustCrypto API.
struct ShaSetting<'a> {
    algorithm: Algorithm,
    salt: &'a [u8],
    params: Params,
}

fn parse_sha_setting(setting: &[u8]) -> Option<ShaSetting<'_>> {
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

    let mut decoded = [0u8; 16];
    let decoded = Base64ShaCrypt::decode(salt, &mut decoded).ok()?;
    let mut canonical = [0u8; 24];
    let encoded = Base64ShaCrypt::encode(decoded, &mut canonical).ok()?;
    if encoded.as_bytes() != salt {
        return None;
    }

    Some(ShaSetting {
        algorithm,
        salt,
        params: Params::new(rounds).ok()?,
    })
}

fn hash_sha(key: &[u8], setting: &[u8], output: &mut [u8; CRYPT_OUTPUT_MAX]) -> Option<usize> {
    let parsed = parse_sha_setting(setting)?;
    let mut decoded_salt = [0u8; 16];
    let decoded_salt = Base64ShaCrypt::decode(parsed.salt, &mut decoded_salt).ok()?;
    let hash = ShaCrypt::new(parsed.algorithm, parsed.params)
        .hash_password_with_salt(key, decoded_salt)
        .ok()?;
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
    // SAFETY: `key` carries the public C ABI's bounded C-string contract.
    let Some(key_length) = (unsafe { cstr_length_bounded(key, CRYPT_KEY_MAX) }) else {
        return unsupported(output);
    };
    // SAFETY: the non-null setting passed the guard above and no accepted
    // profile setting exceeds `CRYPT_SETTING_MAX` bytes.
    let Some(setting_length) = (unsafe { cstr_length_bounded(setting, CRYPT_SETTING_MAX) }) else {
        return unsupported(output);
    };
    // Preserve C callers that reuse a previous `crypt` result or a
    // `crypt_data::__buf` as either input. Both accepted inputs are copied
    // before the result region is written, avoiding overlapping Rust borrows
    // and retaining the historical C read-before-overwrite behavior.
    let mut key_copy = [0u8; CRYPT_KEY_MAX];
    if key_length != 0 {
        // SAFETY: the bounded scan proved this readable key range and the
        // distinct stack array owns exactly the destination range.
        let key = unsafe { core::slice::from_raw_parts(key.cast::<u8>(), key_length) };
        key_copy[..key_length].copy_from_slice(key);
    }
    let mut setting_copy = [0u8; CRYPT_SETTING_MAX];
    if setting_length != 0 {
        // SAFETY: the bounded scan proved this readable setting range and the
        // distinct stack array owns exactly the destination range.
        let setting = unsafe { core::slice::from_raw_parts(setting.cast::<u8>(), setting_length) };
        setting_copy[..setting_length].copy_from_slice(setting);
    }
    let mut result = [0u8; CRYPT_OUTPUT_MAX];
    let Some(length) = hash_sha(
        &key_copy[..key_length],
        &setting_copy[..setting_length],
        &mut result,
    ) else {
        return unsupported(output);
    };
    // SAFETY: successful SHA-crypt output is bounded below the 256-byte
    // `crypt_data::__buf` capacity, including this terminator. Private helper
    // callers have the same sufficient-output-storage obligation.
    let destination = unsafe { core::slice::from_raw_parts_mut(output.cast::<u8>(), length + 1) };
    destination[..length].copy_from_slice(&result[..length]);
    destination[length] = 0;
    output
}

/// Private ABI helper for the deliberately unsupported MD5-crypt format.
///
/// # Safety
///
/// When non-null, `output` must designate writable storage for the `"*\\0"`
/// unsupported marker. The key and setting pointers are not dereferenced.
#[no_mangle]
pub unsafe extern "C" fn __crypt_md5(
    _key: *const c_char,
    _setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    unsupported(output)
}

/// Private ABI helper for RustCrypto-backed SHA-256-crypt.
///
/// # Safety
///
/// Each non-null input pointer must designate a readable NUL-terminated C
/// string for the call. When non-null, `output` must designate writable
/// storage for the selected result and its terminator; this bounded adapter
/// writes fewer than 256 bytes on success. Input and output storage may
/// overlap: accepted inputs are copied before any output write. A null key
/// selects the empty key. A null setting returns the non-null output pointer
/// without modifying its storage.
#[no_mangle]
pub unsafe extern "C" fn __crypt_sha256(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    // SAFETY: this has the public helper's C pointer obligations.
    unsafe { write_sha(key, setting, output) }
}

/// Private ABI helper for RustCrypto-backed SHA-512-crypt.
///
/// # Safety
///
/// Each non-null input pointer must designate a readable NUL-terminated C
/// string for the call. When non-null, `output` must designate writable
/// storage for the selected result and its terminator; this bounded adapter
/// writes fewer than 256 bytes on success. Input and output storage may
/// overlap: accepted inputs are copied before any output write. A null key
/// selects the empty key. A null setting returns the non-null output pointer
/// without modifying its storage.
#[no_mangle]
pub unsafe extern "C" fn __crypt_sha512(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    // SAFETY: this has the public helper's C pointer obligations.
    unsafe { write_sha(key, setting, output) }
}

/// Private ABI helper for the deliberately unsupported bcrypt formats.
///
/// # Safety
///
/// When non-null, `output` must designate writable storage for the `"*\\0"`
/// unsupported marker. The key and setting pointers are not dereferenced.
#[no_mangle]
pub unsafe extern "C" fn __crypt_blowfish(
    _key: *const c_char,
    _setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    unsupported(output)
}

/// Dispatch the bounded SHA-crypt profile through caller-owned `crypt_data`.
///
/// # Safety
///
/// A non-null `data` must point to a writable, aligned 260-byte C
/// `struct crypt_data` for the duration of this call. Non-null key and setting
/// pointers must designate readable NUL-terminated C strings for the call.
/// The record may supply either input through its 256-byte `__buf`; accepted
/// inputs are copied before that region is written. The caller must exclusively
/// own the record for the entire call. A null key selects the empty key; a null
/// setting writes the unsupported `"*\\0"` marker. A null `data` returns null
/// without writing.
unsafe fn crypt_r_dispatch(
    key: *const c_char,
    setting: *const c_char,
    data: *mut c_void,
) -> *mut c_char {
    if data.is_null() {
        return data.cast::<c_char>();
    }
    // SAFETY: `addr_of_mut!` forms no Rust reference to the caller-owned C
    // record; the public ABI's exclusive writable-record obligation supplies
    // the output region.
    let output = unsafe { core::ptr::addr_of_mut!((*data.cast::<CryptData>()).buffer) }
        .cast::<c_char>();
    // SAFETY: this reads at most the three-byte SHA-crypt prefix and stops at
    // an early terminator, so dispatch cannot scan an unbounded setting.
    if unsafe { cstr_starts_with(setting, b"$5$") }
        || unsafe { cstr_starts_with(setting, b"$6$") }
    {
        // SAFETY: the selected SHA profile retains the C-string and output
        // obligations documented by this entry point.
        unsafe { write_sha(key, setting, output) }
    } else {
        unsupported(output)
    }
}

/// Dispatch the bounded SHA-crypt profile through caller-owned `crypt_data`.
#[no_mangle]
pub unsafe extern "C" fn __crypt_r(
    key: *const c_char,
    setting: *const c_char,
    data: *mut c_void,
) -> *mut c_char {
    // SAFETY: this preserves the private helper's C pointer contract.
    unsafe { crypt_r_dispatch(key, setting, data) }
}

static mut CRYPT_DATA: CryptData = CryptData {
    initialized: 0,
    buffer: [0; CRYPT_OUTPUT_MAX],
};

/// Hash through a process-shared 260-byte `struct crypt_data` and return its
/// 256-byte `__buf` result region.
///
/// # Safety
///
/// Each non-null input pointer must designate a readable NUL-terminated C
/// string for the call. The returned pointer is process-shared and is
/// overwritten by the next `crypt` call. Callers must externally serialize
/// all concurrent `crypt` calls; this result record has no internal lock. A
/// null key selects the empty key and a null setting returns the unsupported
/// `"*"` marker in that shared result region.
#[no_mangle]
pub unsafe extern "C" fn crypt(key: *const c_char, setting: *const c_char) -> *mut c_char {
    // SAFETY: the static record has the C header's exact representation.
    unsafe { __crypt_r(key, setting, core::ptr::addr_of_mut!(CRYPT_DATA).cast::<c_void>()) }
}

/// Reentrant caller-buffered form of [`crypt`].
///
/// # Safety
///
/// `data` must point to a writable, aligned 260-byte C `struct crypt_data`
/// for the duration of this call. Each non-null input pointer must designate a
/// readable NUL-terminated C string for the call. The record may supply either
/// input through its `__buf`; accepted inputs are copied before it is written.
/// The caller must exclusively own the record for the entire call. A null key
/// selects the empty key; a null setting writes the unsupported `"*\\0"`
/// marker. A null `data` returns null without writing.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn crypt_r(
    key: *const c_char,
    setting: *const c_char,
    data: *mut c_void,
) -> *mut c_char {
    // SAFETY: this preserves the public C ABI pointer contract.
    unsafe { __crypt_r(key, setting, data) }
}
