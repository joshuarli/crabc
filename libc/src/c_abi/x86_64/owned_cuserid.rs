//! Obsolescent effective-UID account-name C ABI for owned Linux/x86-64.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; `COPYRIGHT` and
//! `compat/upstreams.toml`) maps `src/legacy/cuserid.c::cuserid` (SHA-256
//! `2b535e75996253ab9eb43d77690fb7487538b0c5516722c43a4fd688f365ff40`) to
//! this definition. It is a small C ABI compatibility spelling over the existing
//! local `getpwuid_r` owner, not a login-name policy or a new account source.
//!
//! `cuserid(NULL)` returns process-global storage. Callers serialize that
//! form and use it only until a later null-buffer call overwrites it. A caller
//! buffer must be writable for `L_cuserid` bytes. The copied name is selected
//! from the effective UID's conventional local passwd record; environment
//! variables and provider/NSS lookups are deliberately absent.

use core::{ffi::{c_char, c_long}, mem, ptr};

use super::{owned_passwd, process_context};

const L_CUSERID: usize = 20;
static mut RESULT: [c_char; L_CUSERID] = [0; L_CUSERID];

#[inline]
unsafe fn bounded_name_length(name: *const c_char) -> usize {
    let mut length = 0usize;
    unsafe {
        while length < L_CUSERID && *name.add(length) != 0 {
            length += 1;
        }
    }
    length
}

/// Return the effective UID's local passwd name within the fixed public bound.
///
/// # Safety
/// When non-null, `buffer` is writable for `L_cuserid` bytes. The caller
/// serializes null-buffer calls and their returned shared storage. The local
/// passwd file can change concurrently according to ordinary file semantics;
/// no NSS/provider lookup, environment fallback, or account cache is used.
#[no_mangle]
pub unsafe extern "C" fn cuserid(buffer: *mut c_char) -> *mut c_char {
    unsafe {
        if !buffer.is_null() {
            *buffer = 0;
        }

        let mut password: owned_passwd::Passwd = mem::zeroed();
        let mut password_result: *mut owned_passwd::Passwd = ptr::null_mut();
        // cuserid.c uses long pwb[256], preserving its 2048-byte x86 scratch
        // capacity rather than choosing a new pathname/account buffer policy.
        let mut scratch = [0 as c_long; 256];
        let _ = owned_passwd::getpwuid_r(
            process_context::geteuid(),
            &mut password,
            scratch.as_mut_ptr().cast(),
            mem::size_of_val(&scratch),
            &mut password_result,
        );
        if password_result.is_null() {
            return buffer;
        }

        let length = bounded_name_length(password.name);
        if length == L_CUSERID {
            return buffer;
        }
        let destination = if buffer.is_null() {
            (&raw mut RESULT).cast::<c_char>()
        } else {
            buffer
        };
        ptr::copy_nonoverlapping(password.name, destination, length + 1);
        destination
    }
}
