//! Linux/x86-64 caller-owned mutable-byte-string C ABI closure.
//!
//! This one selected static object translates three pinned musl 1.2.6
//! MIT-licensed source leaves at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`:
//!
//! - `src/misc/dirname.c::dirname` maps to [`dirname`];
//! - `src/string/strcasestr.c::strcasestr` maps to [`strcasestr`]; and
//! - `src/string/strtok_r.c::strtok_r` maps to [`strtok_r`].
//!
//! Their common boundary is caller-owned, NUL-terminated byte storage. The
//! path and tokenizer entries may mutate that storage and `strtok_r`'s
//! continuation slot; `strcasestr` only observes its C strings. In the owned
//! runtimes `strcasestr` keeps musl's public `strlen`/`strncasecmp` calls;
//! otherwise musl's helper calls (`strlen`, `strncasecmp`, `strspn`, and
//! `strcspn`) become local scalar walks so this one archive member has no
//! ambient libc dependency. Musl's
//! `tolower` is the fixed ASCII C-locale fold, so no locale state is selected.
//!
//! The closure owns no static mutable cursor, errno, TLS, locale database,
//! allocator, syscall, pathname lookup, filesystem policy, or runtime state.
//! It is not general string/path/tokenizer support, `strtok`'s historical
//! shared cursor, libc.so, a CRT, loader, sysroot, or public x86 support.

use core::{ffi::c_char, ptr::null_mut};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 stateful byte-string closure requires little-endian Linux/x86-64");

static DOT: [u8; 2] = *b".\0";
static ROOT: [u8; 2] = *b"/\0";
const SLASH: u8 = b'/';

#[inline(always)]
fn static_dot() -> *mut c_char {
    DOT.as_ptr().cast_mut().cast::<c_char>()
}

#[inline(always)]
fn static_root() -> *mut c_char {
    ROOT.as_ptr().cast_mut().cast::<c_char>()
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline(always)]
fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() { byte | 0x20 } else { byte }
}

/// Return whether `byte` occurs in the NUL-terminated separator byte string.
///
/// # Safety
///
/// `separators` must designate a readable NUL-terminated C byte string.
#[inline(always)]
unsafe fn is_separator(mut separators: *const u8, byte: u8) -> bool {
    loop {
        // SAFETY: the helper contract provides this C-string byte.
        let separator = unsafe { separators.read_volatile() };
        if separator == byte {
            return true;
        }
        if separator == 0 {
            return false;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        separators = unsafe { separators.add(1) };
    }
}

/// Implement musl's `strspn` call for the `strtok_r` source closure.
///
/// # Safety
///
/// `cursor` and `separators` must designate readable NUL-terminated C byte
/// strings. `cursor` is mutable only because the public caller later splits
/// the input in place.
#[inline(always)]
unsafe fn skip_separators(mut cursor: *mut u8, separators: *const u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract provides this C-string byte.
        let byte = unsafe { cursor.read_volatile() };
        if byte == 0 || !unsafe { is_separator(separators, byte) } {
            return cursor;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Implement musl's `strcspn` call for the `strtok_r` source closure.
///
/// # Safety
///
/// `cursor` and `separators` must designate readable NUL-terminated C byte
/// strings.
#[inline(always)]
unsafe fn token_end(mut cursor: *mut u8, separators: *const u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract provides this C-string byte.
        let byte = unsafe { cursor.read_volatile() };
        if byte == 0 || unsafe { is_separator(separators, byte) } {
            return cursor;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
}

// Musl's `src/misc/dirname.c` object.
static_archive_member! { dirname_source {
    /// Return the dirname portion with musl's exact caller-buffer mutation.
    ///
    /// Null and empty inputs return immutable `"."`; root-only inputs return
    /// immutable `"/"`. Otherwise `path` must designate a writable,
    /// NUL-terminated C byte string for the complete backward scan. If a directory
    /// prefix exists, this function writes one NUL byte into that caller buffer.
    ///
    /// # Safety
    ///
    /// A non-null `path` must meet the mutable C-string obligations above.
    /// Unterminated, unreadable, or unwritable input is outside musl's direct
    /// dereference contract.
    #[no_mangle]
    pub unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
        if path.is_null() {
            return static_dot();
        }
        let path = path.cast::<u8>();
        // SAFETY: a non-null input has its first byte under the C-string contract.
        if unsafe { path.read_volatile() } == 0 {
            return static_dot();
        }

        let mut index = 0usize;
        // This is musl's strlen(s)-1 start without importing the separately owned
        // byte-string helper.
        while core::hint::black_box(unsafe { path.add(index).read_volatile() }) != 0 {
            index += 1;
        }
        index -= 1;

        loop {
            // SAFETY: `index` stays in the supplied C string.
            if unsafe { path.add(index).read_volatile() } != SLASH {
                break;
            }
            if index == 0 {
                return static_root();
            }
            index -= 1;
        }
        loop {
            // SAFETY: `index` stays in the supplied C string.
            if unsafe { path.add(index).read_volatile() } == SLASH {
                break;
            }
            if index == 0 {
                return static_dot();
            }
            index -= 1;
        }
        loop {
            // SAFETY: `index` stays in the supplied C string.
            if unsafe { path.add(index).read_volatile() } != SLASH {
                break;
            }
            if index == 0 {
                return static_root();
            }
            index -= 1;
        }

        // SAFETY: this is musl's `s[i+1] = 0` in writable caller storage.
        unsafe { path.add(index + 1).write(0) };
        path.cast::<c_char>()
    }
}}

// Musl's `strcasestr` measures the needle with `strlen` and compares with
// `strncasecmp`. The owned runtimes keep those public call edges, so an
// application definition of either reaches this caller as it does in musl.
// Standalone fixture archives use equivalent local scalar walks and keep this
// member free of ambient libc dependencies.
#[cfg(crabc_x86_owned_runtime)]
unsafe extern "C" {
    fn strlen(string: *const c_char) -> usize;
    fn strncasecmp(left: *const c_char, right: *const c_char, count: usize) -> core::ffi::c_int;
}

/// Local `strlen` for the dependency-free fixture member.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated C byte string.
#[cfg(not(crabc_x86_owned_runtime))]
#[inline(always)]
unsafe fn strlen(string: *const c_char) -> usize {
    let mut length = 0usize;
    // SAFETY: every non-NUL observed byte proves the following one.
    while unsafe { string.cast::<u8>().add(length).read_volatile() } != 0 {
        length += 1;
    }
    length
}

/// Local fixed-ASCII `strncasecmp` for the dependency-free fixture member.
///
/// # Safety
///
/// Both pointers must designate bytes through their first NUL or `count`.
#[cfg(not(crabc_x86_owned_runtime))]
#[inline(always)]
unsafe fn strncasecmp(left: *const c_char, right: *const c_char, count: usize) -> core::ffi::c_int {
    let mut offset = 0usize;
    while offset != count {
        // SAFETY: `offset < count` and the caller contract supply both bytes.
        let left_byte = ascii_lower(unsafe { left.cast::<u8>().add(offset).read_volatile() });
        // SAFETY: as above.
        let right_byte = ascii_lower(unsafe { right.cast::<u8>().add(offset).read_volatile() });
        if left_byte == 0 || right_byte == 0 || left_byte != right_byte {
            return core::ffi::c_int::from(left_byte) - core::ffi::c_int::from(right_byte);
        }
        offset += 1;
    }
    0
}

// Musl's `src/string/strcasestr.c` object.
static_archive_member! { strcasestr_source {
    /// Find a case-insensitive ASCII C-byte substring using musl's fixed C fold.
    ///
    /// Both inputs must designate readable NUL-terminated C byte strings. The
    /// returned pointer aliases `haystack`. As in musl, an empty needle matches
    /// at the first haystack position, and an empty haystack never matches.
    ///
    /// # Safety
    ///
    /// Both pointer arguments must satisfy the readable C-string obligations.
    #[no_mangle]
    pub unsafe extern "C" fn strcasestr(
        haystack: *const c_char,
        needle: *const c_char,
    ) -> *mut c_char {
        // SAFETY: the needle is a readable C string under the public contract.
        let length = unsafe { strlen(needle) };
        let mut candidate = haystack;
        // SAFETY: every non-NUL observed haystack byte proves the next byte,
        // and each comparison reads at most through either string's NUL.
        while unsafe { candidate.cast::<u8>().read_volatile() } != 0 {
            if unsafe { strncasecmp(candidate, needle, length) } == 0 {
                return candidate.cast_mut();
            }
            candidate = unsafe { candidate.add(1) };
        }
        null_mut()
    }
}}

// Musl's `src/string/strtok_r.c` object.
static_archive_member! { strtok_r_source {
    /// Split one mutable C byte string with a caller-owned reentrant cursor.
    ///
    /// A non-null `string` starts a sequence; null resumes at `*saveptr`. Leading
    /// separators are skipped, one selected separator becomes NUL, and musl clears
    /// `*saveptr` after the final token or exhaustion.
    ///
    /// # Safety
    ///
    /// `separators` must be a readable NUL-terminated C string; `saveptr` must be
    /// valid writable storage; and a non-null `string` (or resumed `*saveptr`)
    /// must be a writable NUL-terminated C string. The three `restrict` ranges
    /// must not alias. Invalid pointers or unterminated strings are outside the
    /// C contract.
    #[no_mangle]
    pub unsafe extern "C" fn strtok_r(
        string: *mut c_char,
        separators: *const c_char,
        saveptr: *mut *mut c_char,
    ) -> *mut c_char {
        let mut cursor = if string.is_null() {
            // SAFETY: `saveptr` is a readable caller-owned state slot.
            unsafe { saveptr.read() }
        } else {
            string
        }
        .cast::<u8>();
        if cursor.is_null() {
            return null_mut();
        }
        let separators = separators.cast::<u8>();
        // SAFETY: the public C contract supplies both terminated byte strings.
        cursor = unsafe { skip_separators(cursor, separators) };
        // SAFETY: the span scan produced a byte in the supplied C string.
        if unsafe { cursor.read_volatile() } == 0 {
            // SAFETY: the caller owns this continuation slot.
            unsafe { saveptr.write(null_mut()) };
            return null_mut();
        }
        let token = cursor;
        // SAFETY: `token` starts a nonempty mutable C string under the contract.
        cursor = unsafe { token_end(cursor, separators) };
        // SAFETY: the span scan produced a delimiter or the terminator.
        if unsafe { cursor.read_volatile() } == 0 {
            // SAFETY: musl clears this caller-owned continuation after last token.
            unsafe { saveptr.write(null_mut()) };
        } else {
            // SAFETY: `cursor` is a selected writable delimiter byte; the following
            // byte exists because the delimiter is non-NUL.
            unsafe {
                cursor.write(0);
                saveptr.write(cursor.add(1).cast::<c_char>());
            }
        }
        token.cast::<c_char>()
    }
}}
