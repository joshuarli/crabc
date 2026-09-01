//! Linux/x86-64 opt-in static C `a64l` decoder.
//!
//! Pinned musl 1.2.6 provenance is fixed to
//! (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) under musl's MIT license
//! recorded in its `COPYRIGHT` file. The direct source mapping is
//! `src/misc/a64l.c::a64l`: it searches musl's radix-64 digit string for at
//! most six input bytes, packs each found digit at an increasing six-bit
//! offset into `uint32_t`, and returns that value through `int32_t`.
//!
//! Musl's same source file and `a64l.lo` also define the mutable-storage
//! `l64a` encoder. The default x86 static root keeps that distinct owner in
//! `l64a.rs`; this opt-in owner selects only the state-free decoder. It
//! introduces no result buffer, errno/TLS, locale, allocation, syscall, or
//! runtime state.
//!
//! Musl calls `strchr(digits, *s)` for each byte. This target-local leaf
//! deliberately performs the equivalent bounded scan of that fixed immutable
//! 64-byte alphabet instead: it keeps the source's first-invalid-byte and
//! low-to-high packing behavior while avoiding an otherwise broad byte-string
//! archive member. The scan is not a new conversion policy or fallback.
//! This is a private selected-static artifact, not a libc.so, CRT, loader,
//! sysroot, family-completion, promotion, or public x86 support claim.

use core::ffi::{c_char, c_long};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C a64l leaf requires little-endian Linux/x86-64");

/// Musl's exact NUL-terminated low-to-high radix-64 digit string.
static DIGITS: &[u8; 65] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\0";

/// Return the exact table position used by musl's `strchr(digits, byte)`.
///
/// The fixed loop is deliberately bounded to the 64 data bytes, excluding the
/// C terminator. It is the local semantic equivalent of musl's immutable
/// literal search, not a general byte-string API.
#[inline]
fn find_digit(byte: u8) -> Option<u32> {
    let mut index = 0usize;

    while index < 64 {
        if DIGITS[index] == byte {
            return Some(index as u32);
        }
        index += 1;
    }
    None
}

/// Decode up to six musl radix-64 digits from `input`.
///
/// Every valid input byte contributes its digit value at offsets 0, 6, 12,
/// 18, 24, and 30 respectively. Decoding stops at NUL, at the first byte not
/// in `./0-9A-Za-z`, or after six bytes. As in musl, the packed `uint32_t` is
/// converted through `int32_t`, so bit 31 sign-extends in the x86 LP64 `long`
/// result.
///
/// # Safety
///
/// `input` must be non-null and point to a readable NUL-terminated C string.
/// This function reads no more than its first six non-NUL bytes (or the first
/// encountered terminator) and does not write the caller's storage. This local
/// fixed-table scan has no additional C-library dependency.
#[no_mangle]
pub unsafe extern "C" fn a64l(mut input: *const c_char) -> c_long {
    let mut value = 0u32;

    for shift in (0..36).step_by(6) {
        // SAFETY: the caller supplies the readable C-string contract, and the
        // loop advances through at most six non-NUL bytes.
        let byte = unsafe { input.read() } as u8;
        if byte == 0 {
            break;
        }

        let Some(digit) = find_digit(byte) else {
            break;
        };
        value |= digit << shift;

        // SAFETY: this remains within the caller's first six non-NUL bytes.
        input = unsafe { input.add(1) };
    }

    (value as i32) as c_long
}
