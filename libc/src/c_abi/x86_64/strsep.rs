//! Linux/x86-64 selected static C `strsep` leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The complete
//! source closure is `src/string/strsep.c`: it finds the first byte from the
//! delimiter C string in the current token, replaces that byte with NUL, and
//! advances the caller's token pointer; if no delimiter occurs, it clears that
//! pointer after returning the final token. Musl spells the delimiter-set scan
//! through a neighboring string primitive. This leaf retains the same scalar
//! byte traversal locally so its selected archive member has no dependency on
//! a broader string object.
//!
//! This leaf is stateless and allocation-free. It has no errno, TLS, syscall,
//! locale, allocator, mutable runtime, or other C-string entry point. Its only
//! writes are the specified NUL replacement in the caller-owned input string
//! and the caller-owned `char **` state slot. It is a private selected static
//! artifact, not general string/tokenization support, libc.so, a CRT, loader,
//! sysroot, or public x86 support claim.

use core::ffi::c_char;
use core::ptr::null_mut;

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C strsep leaf requires little-endian Linux/x86-64");

/// Split one mutable C token at the first byte selected by `delimiter`.
///
/// # Safety
///
/// `stringp` must be non-null and writable as one `char *` slot. Its current
/// value may be null; otherwise it must designate a writable NUL-terminated
/// C string. `delimiter` must be non-null and designate a readable
/// NUL-terminated C string. The function writes one NUL byte to a selected
/// delimiter in the input string and updates `*stringp` to the next byte or
/// null, exactly as the C contract specifies.
#[no_mangle]
pub unsafe extern "C" fn strsep(
    stringp: *mut *mut c_char,
    delimiter: *const c_char,
) -> *mut c_char {
    // SAFETY: the public contract requires a writable `char *` state slot.
    let token = unsafe { stringp.read() };
    if token.is_null() {
        return null_mut();
    }

    let mut current = token.cast::<u8>();
    loop {
        // SAFETY: a non-null token is a readable NUL-terminated C string,
        // and every prior non-NUL observation established this following byte.
        let byte = unsafe { current.read() };
        if byte == 0 {
            // SAFETY: the state slot is writable under the public contract.
            unsafe { stringp.write(null_mut()) };
            return token;
        }

        let mut candidate = delimiter.cast::<u8>();
        loop {
            // SAFETY: `delimiter` is a readable NUL-terminated C string, so
            // each non-NUL observation establishes the next delimiter byte.
            let delimiter_byte = unsafe { candidate.read() };
            if delimiter_byte == 0 {
                break;
            }
            if byte == delimiter_byte {
                // SAFETY: `current` is one non-NUL byte in the mutable input
                // C string and the state slot remains writable.
                unsafe {
                    current.write(0);
                    stringp.write(current.add(1).cast::<c_char>());
                }
                return token;
            }
            // SAFETY: the observed delimiter byte was non-NUL, so its next
            // byte is supplied by the delimiter C-string contract.
            candidate = unsafe { candidate.add(1) };
        }

        // SAFETY: the observed token byte was non-NUL, so its following byte
        // is supplied by the mutable input C-string contract.
        current = unsafe { current.add(1) };
    }
}
