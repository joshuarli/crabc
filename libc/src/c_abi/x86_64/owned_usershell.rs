//! Local `/etc/shells` C ABI for the owned Linux/x86-64 runtime.
//!
//! This maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; `COPYRIGHT` and
//! `compat/upstreams.toml`) `src/legacy/getusershell.c` (SHA-256
//! `cc9db6faa24725cfc696c9b2cf1d46ca3f936435af6bdc03bc743cce7371d8fa`)
//! directly to the three definitions below. It is conventional-file
//! compatibility machinery, not a
//! login policy, shell validator, account cache, or provider framework.
//!
//! The process-global stream and line are source-owned borrowed storage.
//! Callers serialize `getusershell`, `setusershell`, `endusershell`, and every
//! use of a returned pointer. `setusershell` intentionally does not rewind an
//! existing stream. The fallback is exactly the source's two newline-delimited
//! byte strings, not a system-shell discovery policy.

use core::{ffi::{c_char, c_void}, ptr};

use super::stdio_standard as stdio;
use stdio::StandardStream;

const SHELLS_PATH: &[u8] = b"/etc/shells\0";
const SHELLS_MODE: &[u8] = b"rbe\0";
const FALLBACK_MODE: &[u8] = b"rb\0";
const DEFAULT_SHELLS: &[u8] = b"/bin/sh\n/bin/csh\n";

static mut LINE: *mut c_char = ptr::null_mut();
static mut LINE_SIZE: usize = 0;
static mut STREAM: *mut StandardStream = ptr::null_mut();

unsafe extern "C" {
    fn fmemopen(buffer: *mut c_void, size: usize, mode: *const c_char) -> *mut StandardStream;
}

/// Close the selected `/etc/shells` or fallback stream without freeing the line.
///
/// # Safety
/// Callers serialize this process-global state with every usershell API and
/// returned pointer use. The next `getusershell` opens a fresh stream.
#[no_mangle]
pub unsafe extern "C" fn endusershell() {
    unsafe {
        if !STREAM.is_null() {
            let _ = stdio::fclose(STREAM);
        }
        STREAM = ptr::null_mut();
    }
}

/// Lazily open the shell list, preserving the current stream position.
///
/// # Safety
/// The global-state serialization and borrowed-pointer obligations are those
/// of [`endusershell`]. This function does not rewind an already-open stream.
#[no_mangle]
pub unsafe extern "C" fn setusershell() {
    unsafe {
        if STREAM.is_null() {
            STREAM = stdio::fopen(SHELLS_PATH.as_ptr().cast(), SHELLS_MODE.as_ptr().cast());
        }
        if STREAM.is_null() {
            STREAM = fmemopen(
                DEFAULT_SHELLS.as_ptr().cast_mut().cast(),
                DEFAULT_SHELLS.len(),
                FALLBACK_MODE.as_ptr().cast(),
            );
        }
    }
}

/// Return the next non-comment/nonblank shell line from the current cursor.
///
/// # Safety
/// Callers serialize all usershell APIs and use the returned pointer only
/// until another `getusershell` can reallocate or overwrite its shared line.
/// The line is raw local-file bytes; no UTF-8 or shell-path validation occurs.
#[no_mangle]
pub unsafe extern "C" fn getusershell() -> *mut c_char {
    unsafe {
        if STREAM.is_null() {
            setusershell();
        }
        if STREAM.is_null() {
            return ptr::null_mut();
        }
        loop {
            let length = stdio::getline(&raw mut LINE, &raw mut LINE_SIZE, STREAM);
            if length <= 0 {
                return ptr::null_mut();
            }
            // Match musl exactly: only a first-byte `#` or newline is skipped.
            if *LINE == b'#' as c_char || *LINE == b'\n' as c_char {
                continue;
            }
            if *LINE.add(length as usize - 1) == b'\n' as c_char {
                *LINE.add(length as usize - 1) = 0;
            }
            return LINE;
        }
    }
}
