//! C-locale `regerror` route from musl 1.2.6 `src/regex/regerror.c:7-37`.
//!
//! The source selects the message with its contiguous NUL-separated table,
//! passes it through `LCTRANS_CUR`, and returns `1 + snprintf`.  The admitted
//! x86 static locale profile has no message catalog, so `LCTRANS_CUR` is the
//! identity for its C/POSIX/C.UTF-8 fixed message set.  The byte copy below
//! has the same `snprintf` truncation and required-length result without
//! pulling formatted-output machinery into this private regex owner.

use core::ffi::{c_char, c_int};

use super::types::regex_t;

// `regerror.c:12-29`.  Keeping this one contiguous object retains the source
// table walk and avoids an array of relocated message pointers.
const MESSAGES: &[u8] = concat!(
    "No error\0",
    "No match\0",
    "Invalid regexp\0",
    "Unknown collating element\0",
    "Unknown character class name\0",
    "Trailing backslash\0",
    "Invalid back reference\0",
    "Missing ']'\0",
    "Missing ')'\0",
    "Missing '}'\0",
    "Invalid contents of {}\0",
    "Invalid character range\0",
    "Out of memory\0",
    "Repetition not preceded by valid expression\0",
    // C's adjacent string literal receives its implicit final NUL after
    // `Unknown error`; Rust byte strings need that terminator stated.
    "\0Unknown error\0"
)
.as_bytes();

/// Full `regerror` from musl 1.2.6 `src/regex/regerror.c:31-37`.
///
/// # Safety
///
/// `preg` is ignored as in the C source. If `size` is nonzero, `buf` must
/// designate `size` writable bytes.  The buffer may be null only with zero
/// size, which is the source `snprintf` query form.
#[no_mangle]
pub unsafe extern "C" fn regerror(
    mut error: c_int,
    _preg: *const regex_t,
    buf: *mut c_char,
    size: usize,
) -> usize {
    let mut offset = 0usize;
    // `for (s=messages; e && *s; e--, s+=strlen(s)+1)`: negative error
    // values deliberately walk to the terminal empty string too.
    while error != 0 && MESSAGES[offset] != 0 {
        while MESSAGES[offset] != 0 {
            offset += 1;
        }
        offset += 1;
        error = error.wrapping_sub(1);
    }
    if MESSAGES[offset] == 0 {
        // Select the bytes after the terminal separator: "Unknown error".
        offset += 1;
    }
    let start = offset;
    while MESSAGES[offset] != 0 {
        offset += 1;
    }
    let length = offset - start;
    if size != 0 {
        let copied = core::cmp::min(length, size - 1);
        // SAFETY: the public ABI contract supplies `size` writable bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(MESSAGES.as_ptr().add(start), buf.cast(), copied);
            *buf.add(copied) = 0;
        }
    }
    length + 1
}
