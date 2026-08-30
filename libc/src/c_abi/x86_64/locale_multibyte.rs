//! Selected static Linux/x86-64 named-locale and multibyte C ABI.
//!
//! This leaf owns one deliberately bounded, stateful C text-runtime core:
//! `setlocale`/`localeconv`, `__ctype_get_mb_cur_max`, and the ordinary C
//! multibyte conversion entries from `<stdlib.h>` and `<wchar.h>`. It retains
//! exactly the named `C`, `POSIX`, and `C.UTF-8` global profile. As in musl's
//! built-in map, only `LC_CTYPE` retains `C.UTF-8`; every other selected
//! category remains `C`. `C` and `POSIX` use musl's byte-to-private-code-unit
//! representation while `C.UTF-8` uses musl's UTF-8 state machine. The global
//! selection has a small atomic lock solely for the named category state and `LC_ALL` result
//! serialization; it has no environment lookup, locale database, allocator,
//! locale object, per-thread locale, collation, iconv, wide-stream, syscall,
//! loader, CRT, or general stdio boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/locale/setlocale.c`, `src/locale/locale_map.c`, and
//!   `src/locale/localeconv.c` map to the named-global category selection,
//!   CTYPE-only built-in UTF-8 map, and immutable POSIX `lconv` record.
//! - `src/ctype/__ctype_get_mb_cur_max.c` maps to the active CTYPE width.
//! - `src/multibyte/internal.{h,c}`, `mbrtowc.c`, `wcrtomb.c`, `mbrlen.c`,
//!   `mbsinit.c`, `mblen.c`, `mbtowc.c`, `wctomb.c`, `mbsrtowcs.c`,
//!   `wcsrtombs.c`, `mbstowcs.c`, `wcstombs.c`, `btowc.c`, and `wctob.c`
//!   map to the corresponding entries below.
//!
//! The source's optional environment-backed `setlocale(category, "")`,
//! arbitrary locale-map names, mixed-name parser variants beyond the exact
//! serialized six-category form, locale objects, and per-thread overrides
//! require later ownership work and intentionally remain unselected. An
//! unsupported name or empty environment request returns null without
//! changing the current named state. The null-state `mbrtowc` and `mbrlen`
//! paths retain distinct atomic internal state words like musl's distinct
//! static words; callers requiring one logical conversion must supply a
//! caller-owned `mbstate_t`. `setlocale` is not async-signal-safe, so a signal
//! handler must not re-enter it while the interrupted call owns its lock.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 locale/multibyte leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use super::errno;

const EILSEQ: c_int = 84;

const LC_CTYPE: c_int = 0;
const LC_ALL: c_int = 6;
const LOCALE_CATEGORY_COUNT: usize = 6;
const LC_CTYPE_UTF8_MASK: u8 = 1 << LC_CTYPE;

const MB_RET_ILSEQ: usize = usize::MAX;
const MB_RET_INCOMPLETE: usize = usize::MAX - 1;
const MB_CUR_MAX_C: usize = 1;
const MB_CUR_MAX_UTF8: usize = 4;

const SA: u8 = 0xc2;
const SB: u8 = 0xf4;

// This is musl's `src/multibyte/internal.c` transition table. Its upper
// state bits retain the continuation-byte interval constraints used by OOB.
const BITTAB: [u32; 51] = [
    0xc000_0002, 0xc000_0003, 0xc000_0004, 0xc000_0005, 0xc000_0006, 0xc000_0007,
    0xc000_0008, 0xc000_0009, 0xc000_000a, 0xc000_000b, 0xc000_000c, 0xc000_000d,
    0xc000_000e, 0xc000_000f, 0xc000_0010, 0xc000_0011, 0xc000_0012, 0xc000_0013,
    0xc000_0014, 0xc000_0015, 0xc000_0016, 0xc000_0017, 0xc000_0018, 0xc000_0019,
    0xc000_001a, 0xc000_001b, 0xc000_001c, 0xc000_001d, 0xc000_001e, 0xc000_001f,
    0xb300_0000, 0xc300_0001, 0xc300_0002, 0xc300_0003, 0xc300_0004, 0xc300_0005,
    0xc300_0006, 0xc300_0007, 0xc300_0008, 0xc300_0009, 0xc300_000a, 0xc300_000b,
    0xc300_000c, 0xd300_000d, 0xc300_000e, 0xc300_000f, 0xbb0c_0000, 0xc30c_0001,
    0xc30c_0002, 0xc30c_0003, 0xdb0c_0004,
];

static C_NAME: [u8; 2] = *b"C\0";
static POSIX_NAME: [u8; 6] = *b"POSIX\0";
static UTF8_NAME: [u8; 8] = *b"C.UTF-8\0";

// One C.UTF-8 CTYPE name, five C names, five semicolons, and a terminator.
const LC_ALL_RESULT_BYTES: usize = (UTF8_NAME.len() - 1) + 5 * (C_NAME.len() - 1) + 5 + 1;
static mut LC_ALL_RESULT: [u8; LC_ALL_RESULT_BYTES] = [0; LC_ALL_RESULT_BYTES];
// This stores only the selected LC_CTYPE C.UTF-8 bit. The other five named
// builtin categories are always C, matching musl's `locale_map.c` behavior.
static LOCALE_STATE: AtomicU8 = AtomicU8::new(0);
static LOCALE_LOCK: AtomicBool = AtomicBool::new(false);

// Musl keeps these two null-state conversion channels independent. Atomic
// storage removes a Rust data race without promising that concurrent callers
// share a meaningful conversion sequence; a caller-owned mbstate_t is the
// selected stateful interface.
static MBRTOWC_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);
static MBRLEN_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);

static EMPTY_STRING: [u8; 1] = [0];
static DECIMAL_POINT: [u8; 2] = *b".\0";

/// The public x86 `mbstate_t` layout from `bits/alltypes.h`.
///
/// Musl stores its state machine in only the first opaque word and leaves the
/// second word untouched. C callers must provide one suitably aligned, live
/// `mbstate_t` for the entire conversion sequence and must not race another
/// conversion through the same state object.
#[repr(C)]
pub(super) struct MbState {
    opaque1: u32,
    _opaque2: u32,
}

/// The public x86 `struct lconv` layout from `<locale.h>`.
#[repr(C)]
pub(super) struct Lconv {
    decimal_point: *mut c_char,
    thousands_sep: *mut c_char,
    grouping: *mut c_char,
    int_curr_symbol: *mut c_char,
    currency_symbol: *mut c_char,
    mon_decimal_point: *mut c_char,
    mon_thousands_sep: *mut c_char,
    mon_grouping: *mut c_char,
    positive_sign: *mut c_char,
    negative_sign: *mut c_char,
    int_frac_digits: c_char,
    frac_digits: c_char,
    p_cs_precedes: c_char,
    p_sep_by_space: c_char,
    n_cs_precedes: c_char,
    n_sep_by_space: c_char,
    p_sign_posn: c_char,
    n_sign_posn: c_char,
    int_p_cs_precedes: c_char,
    int_p_sep_by_space: c_char,
    int_n_cs_precedes: c_char,
    int_n_sep_by_space: c_char,
    int_p_sign_posn: c_char,
    int_n_sign_posn: c_char,
}

// Like musl's const `posix_lconv`, this record only refers to immutable
// strings. It is `static mut` solely because the C ABI returns a mutable
// pointer type; Rust never reads or mutates it after initialization.
static mut POSIX_LCONV: Lconv = Lconv {
    decimal_point: DECIMAL_POINT.as_ptr() as *mut c_char,
    thousands_sep: EMPTY_STRING.as_ptr() as *mut c_char,
    grouping: EMPTY_STRING.as_ptr() as *mut c_char,
    int_curr_symbol: EMPTY_STRING.as_ptr() as *mut c_char,
    currency_symbol: EMPTY_STRING.as_ptr() as *mut c_char,
    mon_decimal_point: EMPTY_STRING.as_ptr() as *mut c_char,
    mon_thousands_sep: EMPTY_STRING.as_ptr() as *mut c_char,
    mon_grouping: EMPTY_STRING.as_ptr() as *mut c_char,
    positive_sign: EMPTY_STRING.as_ptr() as *mut c_char,
    negative_sign: EMPTY_STRING.as_ptr() as *mut c_char,
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
    int_p_cs_precedes: 127,
    int_p_sep_by_space: 127,
    int_n_cs_precedes: 127,
    int_n_sep_by_space: 127,
    int_p_sign_posn: 127,
    int_n_sign_posn: 127,
};

#[derive(Clone, Copy)]
struct DecodeOutcome {
    result: usize,
    next_state: u32,
    wide: c_int,
    writes_wide: bool,
    error: bool,
}

#[inline]
fn locale_ctype_is_utf8() -> bool {
    LOCALE_STATE.load(Ordering::Acquire) & (1 << LC_CTYPE) != 0
}

#[inline]
fn codeunit(byte: u8) -> c_int {
    0xdfff & c_int::from(byte as i8)
}

#[inline]
fn is_codeunit(wide: u32) -> bool {
    wide.wrapping_sub(0xdf80) < 0x80
}

#[inline]
fn mb_oob(state: u32, byte: u8) -> u32 {
    let bucket = u32::from(byte >> 3);
    (bucket.wrapping_sub(0x10) | bucket.wrapping_add((state as i32 >> 26) as u32)) & !7
}

#[inline]
fn lock_locale() {
    while LOCALE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn unlock_locale() {
    LOCALE_LOCK.store(false, Ordering::Release);
}

#[inline]
unsafe fn read_state(state: *const MbState) -> u32 {
    // SAFETY: the C caller supplies one readable, properly aligned mbstate_t.
    unsafe { core::ptr::read(state.cast::<u32>()) }
}

#[inline]
unsafe fn write_state(state: *mut MbState, value: u32) {
    // SAFETY: the C caller supplies one writable, properly aligned mbstate_t.
    unsafe { core::ptr::write(state.cast::<u32>(), value) };
}

#[inline]
unsafe fn c_string_equal(value: *const c_char, expected: &[u8]) -> bool {
    for (index, expected_byte) in expected.iter().enumerate() {
        // SAFETY: C string arguments must remain readable through their NUL.
        if unsafe { core::ptr::read(value.cast::<u8>().add(index)) } != *expected_byte {
            return false;
        }
    }
    true
}

#[inline]
unsafe fn named_locale_mode(name: *const c_char) -> Option<bool> {
    if unsafe { c_string_equal(name, &C_NAME) } || unsafe { c_string_equal(name, &POSIX_NAME) } {
        Some(false)
    } else if unsafe { c_string_equal(name, &UTF8_NAME) } {
        Some(true)
    } else {
        None
    }
}

/// Parse one returned mixed `LC_ALL` component, ending at `;` or NUL.
///
/// Only the `C` and `C.UTF-8` spellings occur in this artifact's returned
/// serialization: direct `POSIX` selection normalizes to `C`. The caller has
/// already established that `cursor` points into a valid C string. Returning
/// the delimiter rather than advancing it makes the six-category delimiter
/// rule explicit at the only accepted mixed-form boundary.
unsafe fn parse_locale_component(cursor: *const u8) -> Option<(bool, *const u8)> {
    for (mode, name) in [(false, &C_NAME[..]), (true, &UTF8_NAME[..])] {
        let bytes = &name[..name.len() - 1];
        let mut matches = true;
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: cursor points into the caller's NUL-terminated name.
            if unsafe { core::ptr::read(cursor.add(index)) } != *byte {
                matches = false;
                break;
            }
        }
        if matches {
            // SAFETY: the matched name prefix is readable, and the caller's
            // C string supplies its following delimiter or NUL byte.
            let delimiter = unsafe { cursor.add(bytes.len()) };
            let value = unsafe { core::ptr::read(delimiter) };
            if value == b';' || value == 0 {
                return Some((mode, delimiter));
            }
        }
    }
    None
}

unsafe fn parse_all_locale_state(name: *const c_char) -> Option<u8> {
    if let Some(mode) = unsafe { named_locale_mode(name) } {
        return Some(if mode { LC_CTYPE_UTF8_MASK } else { 0 });
    }

    let mut cursor = name.cast::<u8>();
    let mut state = 0u8;
    for category in 0..LOCALE_CATEGORY_COUNT {
        let (utf8, delimiter) = unsafe { parse_locale_component(cursor) }?;
        // Musl's builtin C.UTF-8 map has an effect only in LC_CTYPE. The
        // returned mixed form therefore contains C.UTF-8 only in component 0.
        if category != LC_CTYPE as usize && utf8 {
            return None;
        }
        if category == LC_CTYPE as usize && utf8 {
            state |= LC_CTYPE_UTF8_MASK;
        }
        // SAFETY: parse_locale_component returned this delimiter within the
        // caller-owned NUL-terminated string.
        let delimiter_value = unsafe { core::ptr::read(delimiter) };
        if category + 1 == LOCALE_CATEGORY_COUNT {
            if delimiter_value != 0 {
                return None;
            }
        } else if delimiter_value != b';' {
            return None;
        } else {
            // SAFETY: the semicolon is followed by the next component in the
            // same C string; its validity is checked on the next iteration.
            cursor = unsafe { delimiter.add(1) };
        }
    }
    // Direct C/POSIX and C.UTF-8 forms have their own spellings. Accept only
    // the one mixed CTYPE-UTF-8 serialization this leaf can return.
    (state == LC_CTYPE_UTF8_MASK).then_some(state)
}

#[inline]
fn locale_name(utf8: bool) -> *mut c_char {
    if utf8 {
        UTF8_NAME.as_ptr() as *mut c_char
    } else {
        C_NAME.as_ptr() as *mut c_char
    }
}

unsafe fn serialize_all_locale_state(state: u8) -> *mut c_char {
    let mut output = core::ptr::addr_of_mut!(LC_ALL_RESULT).cast::<u8>();
    for category in 0..LOCALE_CATEGORY_COUNT {
        let name = if category == LC_CTYPE as usize && state & LC_CTYPE_UTF8_MASK != 0 {
            &UTF8_NAME[..UTF8_NAME.len() - 1]
        } else {
            &C_NAME[..C_NAME.len() - 1]
        };
        for byte in name {
            // SAFETY: LC_ALL_RESULT is sized for one C.UTF-8 name, five C
            // names, all five separators, and its final NUL; the locale lock
            // owns writes.
            unsafe { core::ptr::write(output, *byte) };
            output = unsafe { output.add(1) };
        }
        if category + 1 != LOCALE_CATEGORY_COUNT {
            // SAFETY: the fixed result buffer has room for every separator.
            unsafe { core::ptr::write(output, b';') };
            output = unsafe { output.add(1) };
        }
    }
    // SAFETY: the fixed serialization length leaves this one terminator byte.
    unsafe { core::ptr::write(output, 0) };
    core::ptr::addr_of_mut!(LC_ALL_RESULT).cast::<c_char>()
}

unsafe fn query_locale_locked(category: c_int, state: u8) -> *mut c_char {
    if category == LC_ALL {
        if state == 0 {
            locale_name(false)
        } else {
            // SAFETY: setlocale's mutex owns the reusable mixed-category
            // result buffer until this call returns, matching musl's buffer.
            unsafe { serialize_all_locale_state(state) }
        }
    } else {
        locale_name(category == LC_CTYPE && state & LC_CTYPE_UTF8_MASK != 0)
    }
}

unsafe fn setlocale_locked(category: c_int, name: *const c_char) -> *mut c_char {
    let current = LOCALE_STATE.load(Ordering::Relaxed);
    if name.is_null() {
        // SAFETY: category was range-checked by the public entry point.
        return unsafe { query_locale_locked(category, current) };
    }

    let next = if category == LC_ALL {
        // SAFETY: name is a caller-owned NUL-terminated C string.
        match unsafe { parse_all_locale_state(name) } {
            Some(next) => next,
            None => return core::ptr::null_mut(),
        }
    } else {
        // SAFETY: name is a caller-owned NUL-terminated C string.
        let utf8 = match unsafe { named_locale_mode(name) } {
            Some(utf8) => utf8,
            None => return core::ptr::null_mut(),
        };
        if category == LC_CTYPE && utf8 {
            current | LC_CTYPE_UTF8_MASK
        } else if category == LC_CTYPE {
            current & !LC_CTYPE_UTF8_MASK
        } else {
            current
        }
    };

    LOCALE_STATE.store(next, Ordering::Release);
    // SAFETY: category was range-checked by the public entry point.
    unsafe { query_locale_locked(category, next) }
}

/// Select or query the bounded global C/POSIX/C.UTF-8 category state.
///
/// `locale` must be null or a readable NUL-terminated C string. A non-null
/// name accepts only `C`, `POSIX`, `C.UTF-8`, or the exact six-component
/// semicolon serialization returned for a mixed `LC_ALL` state. The pinned
/// built-in `C.UTF-8` map affects `LC_CTYPE` alone, so a global selection
/// serializes as `C.UTF-8;C;C;C;C;C`. This static artifact intentionally
/// rejects the environment request `""`, arbitrary locale-map names, and
/// locale-object behavior. The returned pointer is libc-owned and may be
/// overwritten by a later `setlocale` call.
#[no_mangle]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if !(LC_CTYPE..=LC_ALL).contains(&category) {
        return core::ptr::null_mut();
    }
    lock_locale();
    // SAFETY: the public caller contract supplies the C string if non-null;
    // the lock owns the global state and mixed-result buffer.
    let result = unsafe { setlocale_locked(category, locale) };
    unlock_locale();
    result
}

/// Return musl's immutable POSIX numeric/monetary locale record.
#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut Lconv {
    core::ptr::addr_of_mut!(POSIX_LCONV)
}

/// Return the active CTYPE maximum multibyte sequence width.
#[no_mangle]
pub extern "C" fn __ctype_get_mb_cur_max() -> usize {
    if locale_ctype_is_utf8() {
        MB_CUR_MAX_UTF8
    } else {
        MB_CUR_MAX_C
    }
}

/// Decode one C-locale code unit or UTF-8 code point with musl's state shape.
///
/// No Rust reference is formed from the caller's source. The result carries
/// exactly the state and errno decision; public wrappers own the specific
/// caller/internal state channel and optional output write.
unsafe fn decode_mbrtowc(current: u32, source: *const c_char, count: usize, utf8: bool) -> DecodeOutcome {
    let mut state = current;
    let mut cursor = source.cast::<u8>();
    let original_count = count;
    let mut remaining = count;

    if cursor.is_null() {
        return if state != 0 {
            DecodeOutcome {
                result: MB_RET_ILSEQ,
                next_state: 0,
                wide: 0,
                writes_wide: false,
                error: true,
            }
        } else {
            DecodeOutcome {
                result: 0,
                next_state: 0,
                wide: 0,
                writes_wide: false,
                error: false,
            }
        };
    }
    if remaining == 0 {
        return DecodeOutcome {
            result: MB_RET_INCOMPLETE,
            next_state: state,
            wide: 0,
            writes_wide: false,
            error: false,
        };
    }

    if state == 0 {
        // SAFETY: count is nonzero and the C API promises the first source
        // byte is readable.
        let first = unsafe { core::ptr::read(cursor) };
        if first < 0x80 {
            return DecodeOutcome {
                result: usize::from(first != 0),
                next_state: 0,
                wide: c_int::from(first),
                writes_wide: true,
                error: false,
            };
        }
        if !utf8 {
            return DecodeOutcome {
                result: 1,
                next_state: 0,
                wide: codeunit(first),
                writes_wide: true,
                error: false,
            };
        }
        if first.wrapping_sub(SA) > SB - SA {
            return DecodeOutcome {
                result: MB_RET_ILSEQ,
                next_state: 0,
                wide: 0,
                writes_wide: false,
                error: true,
            };
        }
        state = BITTAB[usize::from(first - SA)];
        // SAFETY: the lead byte was readable and remaining had at least one.
        cursor = unsafe { cursor.add(1) };
        remaining -= 1;
    }

    if remaining != 0 {
        // SAFETY: remaining nonzero means this continuation candidate is
        // readable under the C API's byte-count contract.
        if mb_oob(state, unsafe { core::ptr::read(cursor) }) != 0 {
            return DecodeOutcome {
                result: MB_RET_ILSEQ,
                next_state: 0,
                wide: 0,
                writes_wide: false,
                error: true,
            };
        }
        loop {
            // SAFETY: the loop consumes only bytes covered by remaining.
            let byte = unsafe { core::ptr::read(cursor) };
            state = (state << 6) | u32::from(byte.wrapping_sub(0x80));
            cursor = unsafe { cursor.add(1) };
            remaining -= 1;
            if state & (1 << 31) == 0 {
                return DecodeOutcome {
                    result: original_count - remaining,
                    next_state: 0,
                    wide: state as c_int,
                    writes_wide: true,
                    error: false,
                };
            }
            if remaining == 0 {
                break;
            }
            // SAFETY: remaining is nonzero, so this next continuation byte
            // belongs to the supplied byte-count range.
            if unsafe { core::ptr::read(cursor) }.wrapping_sub(0x80) >= 0x40 {
                return DecodeOutcome {
                    result: MB_RET_ILSEQ,
                    next_state: 0,
                    wide: 0,
                    writes_wide: false,
                    error: true,
                };
            }
        }
    }

    DecodeOutcome {
        result: MB_RET_INCOMPLETE,
        next_state: state,
        wide: 0,
        writes_wide: false,
        error: false,
    }
}

#[inline]
unsafe fn publish_decode_state(state: *mut MbState, internal: &AtomicU32, value: u32) {
    if state.is_null() {
        internal.store(value, Ordering::Release);
    } else {
        // SAFETY: the public C caller supplied writable mbstate_t storage.
        unsafe { write_state(state, value) };
    }
}

#[inline]
unsafe fn load_decode_state(state: *const MbState, internal: &AtomicU32) -> u32 {
    if state.is_null() {
        internal.load(Ordering::Acquire)
    } else {
        // SAFETY: the public C caller supplied readable mbstate_t storage.
        unsafe { read_state(state) }
    }
}

/// Decode one multibyte sequence while retaining its supplied conversion state.
///
/// `source` must be null or readable for `count` bytes; `wide`, when non-null,
/// must point to writable x86 `wchar_t` storage; and `state`, when non-null,
/// must point to initialized writable x86 `mbstate_t` storage. The null-state
/// channel is intentionally distinct from `mbrlen`'s channel.
#[no_mangle]
pub unsafe extern "C" fn mbrtowc(
    wide: *mut c_int,
    source: *const c_char,
    count: usize,
    state: *mut MbState,
) -> usize {
    // SAFETY: state is null or a caller-owned mbstate_t under this API's C
    // object/lifetime contract.
    let current = unsafe { load_decode_state(state, &MBRTOWC_INTERNAL_STATE) };
    let outcome = unsafe { decode_mbrtowc(current, source, count, locale_ctype_is_utf8()) };
    // SAFETY: same state-storage contract as above.
    unsafe { publish_decode_state(state, &MBRTOWC_INTERNAL_STATE, outcome.next_state) };
    if outcome.error {
        // SAFETY: mbrtowc's EILSEQ result belongs to the calling C thread.
        unsafe { errno::set_errno(EILSEQ) };
    }
    if outcome.writes_wide && !wide.is_null() {
        // SAFETY: the C caller supplied writable wchar_t storage; x86
        // wchar_t is the same 32-bit signed ABI as c_int.
        unsafe { core::ptr::write(wide, outcome.wide) };
    }
    outcome.result
}

/// Encode one C-locale code unit or UTF-8 code point.
///
/// `destination`, when non-null, must have room for four bytes. Musl ignores
/// its `mbstate_t` argument because both selected encodings are stateless for
/// output; this translation retains that ABI shape without modifying it.
#[no_mangle]
pub unsafe extern "C" fn wcrtomb(
    destination: *mut c_char,
    wide: c_int,
    _state: *mut MbState,
) -> usize {
    if destination.is_null() {
        return 1;
    }
    let wide_unsigned = wide as u32;
    if wide_unsigned < 0x80 {
        // SAFETY: caller supplied a writable destination byte.
        unsafe { core::ptr::write(destination, wide as c_char) };
        return 1;
    }
    if !locale_ctype_is_utf8() {
        if !is_codeunit(wide_unsigned) {
            // SAFETY: this C conversion error belongs to the calling thread.
            unsafe { errno::set_errno(EILSEQ) };
            return MB_RET_ILSEQ;
        }
        // SAFETY: caller supplied a writable destination byte.
        unsafe { core::ptr::write(destination, wide as c_char) };
        return 1;
    }
    if wide_unsigned < 0x800 {
        // SAFETY: caller supplied room for the selected maximum of four bytes.
        unsafe {
            core::ptr::write(destination, (0xc0 | (wide_unsigned >> 6)) as c_char);
            core::ptr::write(destination.add(1), (0x80 | (wide_unsigned & 0x3f)) as c_char);
        }
        return 2;
    }
    if wide_unsigned < 0xd800 || wide_unsigned.wrapping_sub(0xe000) < 0x2000 {
        // SAFETY: caller supplied room for the selected maximum of four bytes.
        unsafe {
            core::ptr::write(destination, (0xe0 | (wide_unsigned >> 12)) as c_char);
            core::ptr::write(destination.add(1), (0x80 | ((wide_unsigned >> 6) & 0x3f)) as c_char);
            core::ptr::write(destination.add(2), (0x80 | (wide_unsigned & 0x3f)) as c_char);
        }
        return 3;
    }
    if wide_unsigned.wrapping_sub(0x10000) < 0x100000 {
        // SAFETY: caller supplied room for the selected maximum of four bytes.
        unsafe {
            core::ptr::write(destination, (0xf0 | (wide_unsigned >> 18)) as c_char);
            core::ptr::write(destination.add(1), (0x80 | ((wide_unsigned >> 12) & 0x3f)) as c_char);
            core::ptr::write(destination.add(2), (0x80 | ((wide_unsigned >> 6) & 0x3f)) as c_char);
            core::ptr::write(destination.add(3), (0x80 | (wide_unsigned & 0x3f)) as c_char);
        }
        return 4;
    }
    // SAFETY: this C conversion error belongs to the calling thread.
    unsafe { errno::set_errno(EILSEQ) };
    MB_RET_ILSEQ
}

/// Report whether a supplied multibyte state is in its initial state.
///
/// A non-null `state` must point to initialized readable x86 `mbstate_t`
/// storage.
#[no_mangle]
pub unsafe extern "C" fn mbsinit(state: *const MbState) -> c_int {
    if state.is_null() {
        1
    } else {
        // SAFETY: the caller supplied readable mbstate_t storage.
        (unsafe { read_state(state) } == 0) as c_int
    }
}

/// Decode one multibyte sequence without retaining a caller-visible state.
///
/// `source` must be null or readable for `count` bytes, and a non-null `wide`
/// must point to writable x86 `wchar_t` storage.
#[no_mangle]
pub unsafe extern "C" fn mbtowc(
    wide: *mut c_int,
    source: *const c_char,
    count: usize,
) -> c_int {
    if source.is_null() {
        return 0;
    }
    let outcome = unsafe { decode_mbrtowc(0, source, count, locale_ctype_is_utf8()) };
    if outcome.error || outcome.result == MB_RET_INCOMPLETE {
        // Unlike mbrtowc, musl's legacy mbtowc reports an incomplete input as
        // EILSEQ/-1 rather than the restartable -2 result.
        if !outcome.error {
            // SAFETY: this legacy conversion failure belongs to this thread.
            unsafe { errno::set_errno(EILSEQ) };
        } else {
            // SAFETY: decode_mbrtowc identified a malformed byte sequence.
            unsafe { errno::set_errno(EILSEQ) };
        }
        return -1;
    }
    if outcome.writes_wide && !wide.is_null() {
        // SAFETY: caller supplied writable wchar_t storage when non-null.
        unsafe { core::ptr::write(wide, outcome.wide) };
    }
    outcome.result as c_int
}

/// Decode one multibyte sequence through mbrtowc's distinct internal channel.
///
/// `source` must be null or readable for `count` bytes. A non-null `state`
/// must point to initialized writable x86 `mbstate_t` storage.
#[no_mangle]
pub unsafe extern "C" fn mbrlen(
    source: *const c_char,
    count: usize,
    state: *mut MbState,
) -> usize {
    // SAFETY: state is null or a caller-owned mbstate_t under the C API.
    let current = unsafe { load_decode_state(state, &MBRLEN_INTERNAL_STATE) };
    let outcome = unsafe { decode_mbrtowc(current, source, count, locale_ctype_is_utf8()) };
    // SAFETY: same state-storage contract as above.
    unsafe { publish_decode_state(state, &MBRLEN_INTERNAL_STATE, outcome.next_state) };
    if outcome.error {
        // SAFETY: mbrlen inherits mbrtowc's EILSEQ publication.
        unsafe { errno::set_errno(EILSEQ) };
    }
    outcome.result
}

/// Legacy mblen adapter over musl's stateless mbtowc route.
///
/// `source` must be null or readable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn mblen(source: *const c_char, count: usize) -> c_int {
    unsafe { mbtowc(core::ptr::null_mut(), source, count) }
}

/// Legacy wctomb adapter over the selected stateless output route.
///
/// A non-null `destination` must point to writable storage for four bytes.
#[no_mangle]
pub unsafe extern "C" fn wctomb(destination: *mut c_char, wide: c_int) -> c_int {
    if destination.is_null() {
        return 0;
    }
    let result = unsafe { wcrtomb(destination, wide, core::ptr::null_mut()) };
    if result == MB_RET_ILSEQ {
        -1
    } else {
        result as c_int
    }
}

#[inline]
unsafe fn c_string_len(source: *const u8) -> usize {
    let mut cursor = source;
    let mut length = 0usize;
    // SAFETY: C string callers supply a readable terminating NUL byte.
    while unsafe { core::ptr::read(cursor) } != 0 {
        cursor = unsafe { cursor.add(1) };
        length = length.wrapping_add(1);
    }
    length
}

/// Convert a NUL-terminated multibyte string into wide characters.
///
/// `source` must point to a live writable pointer to a readable NUL-terminated
/// C string. When `destination` is non-null it must hold `count` wide slots.
/// `state` must be null or point to initialized writable x86 `mbstate_t`
/// storage.
/// Initial-state source/destination/count behavior and a caller-owned,
/// noninitial UTF-8 resume with positive output capacity are selected. A
/// caller-owned noninitial `mbsrtowcs` state with zero output capacity is
/// deliberately outside this artifact; ordinary null-state conversions use no
/// hidden state, as in musl's `mbsrtowcs`.
#[no_mangle]
pub unsafe extern "C" fn mbsrtowcs(
    destination: *mut c_int,
    source: *mut *const c_char,
    count: usize,
    state: *mut MbState,
) -> usize {
    // SAFETY: source is a caller-owned readable pointer-to-pointer object.
    let mut cursor = unsafe { core::ptr::read(source) }.cast::<u8>();
    let utf8_now = locale_ctype_is_utf8();
    let initial_state = if state.is_null() {
        0
    } else {
        // SAFETY: the caller supplied readable mbstate_t storage.
        unsafe { read_state(state) }
    };
    // Musl resumes a pre-existing state before inspecting the current locale.
    // After that resume label it remains on its UTF-8 path for this call.
    let force_utf8 = initial_state != 0;

    if destination.is_null() {
        if initial_state == 0 && !utf8_now {
            // SAFETY: source is a valid NUL-terminated C byte string.
            return unsafe { c_string_len(cursor) };
        }

        let mut produced = 0usize;
        let mut pending = initial_state;
        loop {
            // A zero state followed by NUL terminates the input. A pending
            // state treats that NUL as an invalid continuation just like musl.
            if pending == 0 {
                // SAFETY: source is a readable NUL-terminated C string.
                let first = unsafe { core::ptr::read(cursor) };
                if first == 0 {
                    return produced;
                }
                if !utf8_now && !force_utf8 {
                    cursor = unsafe { cursor.add(1) };
                    produced = produced.wrapping_add(1);
                    continue;
                }
            }
            let outcome = unsafe { decode_mbrtowc(pending, cursor.cast(), 4, true) };
            if outcome.error || outcome.result == MB_RET_INCOMPLETE {
                // SAFETY: mbsrtowcs reports malformed or incomplete input as
                // EILSEQ; count mode leaves source and caller state untouched.
                unsafe { errno::set_errno(EILSEQ) };
                return MB_RET_ILSEQ;
            }
            cursor = unsafe { cursor.add(outcome.result) };
            produced = produced.wrapping_add(1);
            pending = 0;
        }
    }

    let initial_count = count;
    let mut remaining = count;
    let mut output = destination;
    let mut pending = initial_state;
    if pending != 0 {
        // Musl clears a caller state before its output-producing resume path.
        // SAFETY: state is non-null because pending came from it.
        unsafe { write_state(state, 0) };
    }

    loop {
        if pending == 0 {
            if remaining == 0 {
                // SAFETY: caller supplied a writable source pointer object.
                unsafe { core::ptr::write(source, cursor.cast()) };
                return initial_count;
            }
            // SAFETY: source is a readable NUL-terminated C string.
            let first = unsafe { core::ptr::read(cursor) };
            if first == 0 {
                // SAFETY: destination has at least one slot because remaining
                // is nonzero, and source is the caller's writable pointer.
                unsafe {
                    core::ptr::write(output, 0);
                    core::ptr::write(source, core::ptr::null());
                }
                return initial_count - remaining;
            }
            if !utf8_now && !force_utf8 {
                // SAFETY: destination has one remaining slot and cursor has
                // one readable non-NUL source byte.
                unsafe { core::ptr::write(output, codeunit(first)) };
                output = unsafe { output.add(1) };
                cursor = unsafe { cursor.add(1) };
                remaining -= 1;
                continue;
            }
        }

        let outcome = unsafe { decode_mbrtowc(pending, cursor.cast(), 4, true) };
        if outcome.error || outcome.result == MB_RET_INCOMPLETE {
            // SAFETY: mbsrtowcs returns the start of the invalid sequence for
            // ordinary input. Pending-state pointer details are unselected;
            // the caller still receives EILSEQ and a valid source pointer.
            unsafe {
                errno::set_errno(EILSEQ);
                core::ptr::write(source, cursor.cast());
            }
            return MB_RET_ILSEQ;
        }
        // The normal branch established remaining > 0. A pending resume with
        // zero count is not a selected caller pattern; complete its one code
        // point only when the caller supplied output capacity.
        if remaining == 0 {
            // SAFETY: caller-owned source pointer remains valid on this
            // bounded rejected resume case; report no conversion rather than
            // creating a Rust out-of-bounds write.
            unsafe { core::ptr::write(source, cursor.cast()) };
            return initial_count;
        }
        // SAFETY: destination has one remaining wchar_t slot.
        unsafe { core::ptr::write(output, outcome.wide) };
        output = unsafe { output.add(1) };
        cursor = unsafe { cursor.add(outcome.result) };
        remaining -= 1;
        pending = 0;
    }
}

/// Convert a NUL-terminated wide string into multibyte bytes.
///
/// `source` must point to a live writable pointer to a readable terminated x86
/// `wchar_t` sequence. A non-null destination must hold `count` bytes. Musl
/// ignores its mbstate_t argument for this stateless output conversion.
#[no_mangle]
pub unsafe extern "C" fn wcsrtombs(
    destination: *mut c_char,
    source: *mut *const c_int,
    count: usize,
    _state: *mut MbState,
) -> usize {
    // SAFETY: source is a caller-owned readable pointer-to-pointer object.
    let mut cursor = unsafe { core::ptr::read(source) };

    if destination.is_null() {
        let mut total = 0usize;
        loop {
            // SAFETY: source points through a NUL-terminated wide sequence.
            let wide = unsafe { core::ptr::read(cursor) };
            if wide == 0 {
                return total;
            }
            if (wide as u32) >= 0x80 {
                let mut bytes = [0 as c_char; 4];
                let encoded = unsafe { wcrtomb(bytes.as_mut_ptr(), wide, core::ptr::null_mut()) };
                if encoded == MB_RET_ILSEQ {
                    return MB_RET_ILSEQ;
                }
                total = total.wrapping_add(encoded);
            } else {
                total = total.wrapping_add(1);
            }
            cursor = unsafe { cursor.add(1) };
        }
    }

    let initial_count = count;
    let mut remaining = count;
    let mut output = destination;
    while remaining >= 4 {
        // SAFETY: source points through a NUL-terminated wide sequence.
        let wide = unsafe { core::ptr::read(cursor) };
        if (wide as u32).wrapping_sub(1) >= 0x7f {
            if wide == 0 {
                // SAFETY: output has room and source is a writable pointer.
                unsafe {
                    core::ptr::write(output, 0);
                    core::ptr::write(source, core::ptr::null());
                }
                return initial_count - remaining;
            }
            let encoded = unsafe { wcrtomb(output, wide, core::ptr::null_mut()) };
            if encoded == MB_RET_ILSEQ {
                return MB_RET_ILSEQ;
            }
            output = unsafe { output.add(encoded) };
            remaining -= encoded;
        } else {
            // SAFETY: output has at least one remaining byte slot.
            unsafe { core::ptr::write(output, wide as c_char) };
            output = unsafe { output.add(1) };
            remaining -= 1;
        }
        cursor = unsafe { cursor.add(1) };
    }

    while remaining != 0 {
        // SAFETY: source points through a NUL-terminated wide sequence.
        let wide = unsafe { core::ptr::read(cursor) };
        if (wide as u32).wrapping_sub(1) >= 0x7f {
            if wide == 0 {
                // SAFETY: output has at least one remaining byte slot.
                unsafe {
                    core::ptr::write(output, 0);
                    core::ptr::write(source, core::ptr::null());
                }
                return initial_count - remaining;
            }
            let mut bytes = [0 as c_char; 4];
            let encoded = unsafe { wcrtomb(bytes.as_mut_ptr(), wide, core::ptr::null_mut()) };
            if encoded == MB_RET_ILSEQ {
                return MB_RET_ILSEQ;
            }
            if encoded > remaining {
                // SAFETY: the current wide code point did not fit, so musl
                // leaves the caller's source at that unconverted element.
                unsafe { core::ptr::write(source, cursor) };
                return initial_count - remaining;
            }
            // SAFETY: encoded is at most remaining and the source scratch is
            // initialized by wcrtomb for exactly encoded bytes.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, encoded) };
            output = unsafe { output.add(encoded) };
            remaining -= encoded;
        } else {
            // SAFETY: output has at least one remaining byte slot.
            unsafe { core::ptr::write(output, wide as c_char) };
            output = unsafe { output.add(1) };
            remaining -= 1;
        }
        cursor = unsafe { cursor.add(1) };
    }
    // SAFETY: source is the caller's writable pointer-to-pointer object.
    unsafe { core::ptr::write(source, cursor) };
    initial_count
}

/// Legacy null-state adapter over mbsrtowcs.
///
/// `source` must point to a readable NUL-terminated C string, and a non-null
/// `destination` must hold `count` x86 `wchar_t` slots.
#[no_mangle]
pub unsafe extern "C" fn mbstowcs(
    destination: *mut c_int,
    source: *const c_char,
    count: usize,
) -> usize {
    let mut source = source;
    // SAFETY: forwards the legacy C string and destination contract directly.
    unsafe { mbsrtowcs(destination, &mut source, count, core::ptr::null_mut()) }
}

/// Legacy null-state adapter over wcsrtombs.
///
/// `source` must point to a readable NUL-terminated x86 `wchar_t` sequence,
/// and a non-null `destination` must hold `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn wcstombs(
    destination: *mut c_char,
    source: *const c_int,
    count: usize,
) -> usize {
    let mut source = source;
    // SAFETY: forwards the legacy wide-string and destination contract.
    unsafe { wcsrtombs(destination, &mut source, count, core::ptr::null_mut()) }
}

/// Convert one byte to a wide C code unit under the active CTYPE mode.
#[no_mangle]
pub extern "C" fn btowc(value: c_int) -> u32 {
    let byte = value as u8;
    if byte < 0x80 {
        u32::from(byte)
    } else if !locale_ctype_is_utf8() && value != -1 {
        codeunit(byte) as u32
    } else {
        u32::MAX
    }
}

/// Convert one wide C code unit to a byte under the active CTYPE mode.
#[no_mangle]
pub extern "C" fn wctob(value: u32) -> c_int {
    if value < 0x80 {
        value as c_int
    } else if !locale_ctype_is_utf8() && is_codeunit(value) {
        value as u8 as c_int
    } else {
        -1
    }
}
