//! Selected Linux/x86-64 C `hstrerror` message lookup.
//!
//! This leaf owns exactly the immutable message selection of musl 1.2.6's
//! `src/network/hstrerror.c`. Its packed source-order message sequence keeps
//! the four conventional positive `h_errno` values followed by the empty
//! sentinel and `Unknown error` fallback. The selected C/POSIX/C.UTF-8
//! profiles have no message catalog translation, so musl's `LCTRANS_CUR`
//! result is the source string itself here. That fixed-profile identity is an
//! explicit boundary: arbitrary locale catalogs and locale-state lookup are
//! not silently emulated.
//!
//! The function neither reads nor writes `h_errno`; it has no hosts-file,
//! resolver-configuration, DNS, network-database, errno, TLS, allocation,
//! stdio, syscall, or mutable-state dependency. Returned storage is immutable
//! process-static data and C callers must neither modify nor free it.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/network/hstrerror.c` maps to [`hstrerror`]. The source's `LCTRANS_CUR`
//! locale-catalog hook is intentionally identity-only for the selected fixed
//! profiles; `src/locale/locale_map.c` and message catalogs remain unselected.

use core::ffi::{c_char, c_int};

// Retain musl's packed message order, including the empty sentinel before the
// fallback. The explicit empty entry lets a positive nonstandard h_errno code
// stop at the same `Unknown error` fallback as musl's source loop.
static MESSAGES: &[u8] = b"Host not found\0Try again\0Non-recoverable error\0Address not available\0\0Unknown error\0";
const UNKNOWN_OFFSET: usize = MESSAGES.len() - b"Unknown error\0".len();

/// Return the selected fixed-profile message start for one C `h_errno` value.
///
/// The musl loop decrements its code while it advances over NUL-terminated
/// messages, then skips the empty sentinel to the unknown fallback. The
/// explicit nonpositive guard preserves the pinned oracle's observed fallback
/// while keeping the Rust traversal inside the immutable sequence.
#[inline(always)]
fn message_offset(error: c_int) -> usize {
    if error <= 0 {
        return UNKNOWN_OFFSET;
    }

    let mut offset = 0usize;
    let mut remaining = error;
    let bytes = MESSAGES.as_ptr();
    // SAFETY: `offset` starts at the first byte of the fixed sequence. Each
    // inner traversal stops at a NUL inside that sequence, then advances to
    // the next entry. The extra empty sentinel ends the outer traversal before
    // it could advance past the final `Unknown error` entry.
    while remaining > 1 && unsafe { bytes.add(offset).read_volatile() } != 0 {
        // SAFETY: the outer condition establishes that `offset` starts a
        // NUL-terminated entry in the immutable sequence. Its terminator is
        // reached before any increment could leave the sequence.
        while unsafe { bytes.add(offset).read_volatile() } != 0 {
            offset += 1;
        }
        remaining -= 1;
        offset += 1;
    }

    // SAFETY: the loop invariant keeps `offset` at an entry start or the
    // sentinel; both positions designate a byte inside `MESSAGES`.
    if unsafe { bytes.add(offset).read_volatile() } == 0 {
        UNKNOWN_OFFSET
    } else {
        offset
    }
}

/// Return musl's immutable h_errno message for the selected locale profiles.
///
/// The returned pointer stays valid for the process lifetime and designates
/// immutable NUL-terminated storage. It is independent of the current value
/// of `h_errno` and does not modify `errno`.
#[no_mangle]
pub extern "C" fn hstrerror(error: c_int) -> *const c_char {
    let offset = message_offset(error);
    // SAFETY: `message_offset` returns either a start inside `MESSAGES` or
    // `UNKNOWN_OFFSET`, which is the start of its final NUL-terminated entry.
    unsafe { MESSAGES.as_ptr().add(offset).cast() }
}
