//! Owned SysV/XSI message formatting through the runtime's descriptor printf.
//!
//! Semantic translation of musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, `src/misc/fmtmsg.c`
//! (SHA-256 `27354c57b1827561585a73dbe9f2d7f97cd73563d4043cf2907912c8faaebb6e`).
//! That file explicitly dedicates this implementation to the public domain:
//! "Public domain fmtmsg(); Written by Isaac Dunham, 2014". Its `_strcolcmp`
//! maps to [`component_mismatch`] and its `fmtmsg` maps to [`fmtmsg`] plus the
//! private [`msgverb_mask`] parser. The surrounding musl distribution is MIT
//! licensed; this source-specific public-domain notice is retained separately.
//!
//! The console route ignores `MSGVERB`, both routes use the existing owned
//! `dprintf`, and cancellation stays disabled until the console descriptor is
//! closed and stderr formatting has finished. Restoring the prior state is
//! not an invented cancellation point. This owner leaves the frozen selected
//! `legacy_misc` piece writer and paused shared implementation unchanged.

use core::ffi::{c_char, c_int, c_long};
use core::ptr::{null, null_mut};

use super::{byte_strings, descriptor_entry, descriptor_io, environment, pthread_cancel};

// The formatter owner is private beneath stdio_format_scan. Reuse its C ABI
// seam exactly as owned_syslog does, without exposing a new Rust interface.
unsafe extern "C" {
    fn dprintf(fd: c_int, format: *const c_char, ...) -> c_int;
}

const MM_PRINT: c_long = 256;
const MM_CONSOLE: c_long = 512;
const MM_NOTOK: c_int = -1;
const MM_NOMSG: c_int = 1;
const MM_NOCON: c_int = 4;

/// Compare a source component with one colon-delimited environment component.
/// Both pointers name readable NUL-terminated strings; `actual` may contain
/// further components after its first colon.
unsafe fn component_mismatch(wanted: *const u8, actual: *const u8) -> bool {
    let mut index = 0usize;
    while unsafe { wanted.add(index).read() } != 0
        && unsafe { actual.add(index).read() } != 0
        && unsafe { wanted.add(index).read() == actual.add(index).read() }
    {
        index += 1;
    }
    unsafe {
        wanted.add(index).read() != 0
            || (actual.add(index).read() != 0 && actual.add(index).read() != b':')
    }
}

/// Musl treats an absent/empty list or any unknown component as all pieces.
/// `cursor` is null or a readable NUL-terminated environment string retained
/// across the call, under the normal C environment mutation obligations.
unsafe fn msgverb_mask(mut cursor: *mut c_char) -> c_int {
    static COMPONENTS: [&[u8]; 5] = [
        b"label\0", b"severity\0", b"text\0", b"action\0", b"tag\0",
    ];
    let mut mask = 0;
    while !cursor.is_null() && unsafe { cursor.read() } != 0 {
        let mut component = 0;
        while component < COMPONENTS.len()
            && unsafe { component_mismatch(COMPONENTS[component].as_ptr(), cursor.cast()) }
        {
            component += 1;
        }
        if component == COMPONENTS.len() {
            return 0xff;
        }
        mask |= 1 << component;
        let colon = unsafe { byte_strings::strchr(cursor, b':' as c_int) };
        cursor = if colon.is_null() { null_mut() } else { unsafe { colon.add(1) } };
    }
    if mask == 0 { 0xff } else { mask }
}

/// Format the SysV/XSI label, severity, text, action, and tag message.
///
/// `MM_CONSOLE` opens and closes `/dev/console` independently of `MM_PRINT`,
/// which borrows fd 2 and obeys `MSGVERB`. Errors compose to `MM_NOMSG`,
/// `MM_NOCON`, or `MM_NOTOK`; console close errors do not change the result.
/// The owned cancellation state is disabled around both routes and restored
/// after their descriptor/output cleanup, matching the pinned source.
///
/// # Safety
/// Every non-null string pointer names a readable NUL-terminated C string for
/// the whole call. The caller runs on an initialized owned runtime thread and
/// obeys the C environment's concurrent mutation contract. Caller-controlled
/// descriptors retain their normal lifetime, blocking and SIGPIPE obligations.
#[no_mangle]
pub unsafe extern "C" fn fmtmsg(
    classification: c_long,
    label: *const c_char,
    severity: c_int,
    text: *const c_char,
    action: *const c_char,
    tag: *const c_char,
) -> c_int {
    // Source ordering captures MSGVERB before the cancellation transition.
    let cmsg = unsafe { environment::getenv(c"MSGVERB".as_ptr()) };
    let mut previous = 0;
    // Valid owned tasks always have cancellation state. As with owned syslog,
    // reject a foreign task before entering an unprotected descriptor path.
    if unsafe { pthread_cancel::pthread_setcancelstate(1, &mut previous) } != 0 {
        return MM_NOTOK;
    }
    let severity_text = match severity {
        1 => c"HALT: ".as_ptr(),
        2 => c"ERROR: ".as_ptr(),
        3 => c"WARNING: ".as_ptr(),
        4 => c"INFO: ".as_ptr(),
        // MM_NULLSEV is integer zero in the C source's pointer initializer.
        // Unknown nonzero severities therefore reach dprintf as null %s;
        // preserve that formatter behavior rather than substituting empty.
        _ => null(),
    };
    let empty = c"".as_ptr();
    let mut result = 0;
    if classification & MM_CONSOLE != 0 {
        let console = unsafe { descriptor_entry::open(c"/dev/console".as_ptr(), 1, 0) };
        if console < 0 {
            result = MM_NOCON;
        } else {
            // SAFETY: the eight pointer arguments match eight %s conversions.
            // Caller strings satisfy the API contract, null optional pieces
            // become static empty strings, and severity preserves source %s.
            let wrote = unsafe {
                dprintf(
                    console, c"%s%s%s%s%s%s%s%s\n".as_ptr(),
                    if label.is_null() { empty } else { label },
                    if label.is_null() { empty } else { c": ".as_ptr() },
                    if severity == 0 { empty } else { severity_text },
                    if text.is_null() { empty } else { text },
                    if action.is_null() { empty } else { c"\nTO FIX: ".as_ptr() },
                    if action.is_null() { empty } else { action },
                    if action.is_null() { empty } else { c" ".as_ptr() },
                    if tag.is_null() { empty } else { tag },
                )
            };
            if wrote < 1 { result = MM_NOCON; }
            let _ = descriptor_io::close(console);
        }
    }
    if classification & MM_PRINT != 0 {
        let verb = unsafe { msgverb_mask(cmsg) };
        // SAFETY: this is the same fixed formatter contract as the console
        // route. Component selection changes only which valid strings pass.
        let wrote = unsafe {
            dprintf(
                2, c"%s%s%s%s%s%s%s%s\n".as_ptr(),
                if verb & 1 != 0 && !label.is_null() { label } else { empty },
                if verb & 1 != 0 && !label.is_null() { c": ".as_ptr() } else { empty },
                if verb & 2 != 0 && severity != 0 { severity_text } else { empty },
                if verb & 4 != 0 && !text.is_null() { text } else { empty },
                if verb & 8 != 0 && !action.is_null() { c"\nTO FIX: ".as_ptr() } else { empty },
                if verb & 8 != 0 && !action.is_null() { action } else { empty },
                if verb & 8 != 0 && !action.is_null() { c" ".as_ptr() } else { empty },
                if verb & 16 != 0 && !tag.is_null() { tag } else { empty },
            )
        };
        if wrote < 1 { result |= MM_NOMSG; }
    }
    if result & (MM_NOCON | MM_NOMSG) == MM_NOCON | MM_NOMSG {
        result = MM_NOTOK;
    }
    // SAFETY: the successful transition above supplied this exact prior state;
    // all owned console descriptors and printf buffers are released already.
    let _ = unsafe { pthread_cancel::pthread_setcancelstate(previous, null_mut()) };
    result
}
