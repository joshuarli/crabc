//! Selected static Linux/x86-64 C11 `<uchar.h>` stateful conversion block.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps the following MIT-licensed
//! source bodies to this one target-private module:
//!
//! - `src/multibyte/c16rtomb.c::c16rtomb`;
//! - `src/multibyte/mbrtoc16.c::mbrtoc16`; and
//! - `src/multibyte/mbrtoc32.c::mbrtoc32`.
//!
//! The block deliberately delegates all byte decoding and scalar encoding to
//! the already selected `mbrtowc` and `wcrtomb` owners in
//! `locale_multibyte.rs`. That preserves the established C/POSIX/C.UTF-8
//! profile, locale-object CTYPE override, first-word-only `mbstate_t` layout,
//! and initial-exec errno substrate without making this a second locale or
//! conversion core. Its only additional state is musl's three separate
//! null-`mbstate_t` words: one per public C11 entry. Atomic storage follows
//! the established `mbrtowc` null-state owner: it removes a Rust data race
//! without making concurrent null-state calls one meaningful conversion
//! sequence. Callers that need an independent sequence supply an `mbstate_t`.
//!
//! The pending-low-surrogate encoding used by `mbrtoc16` is intentionally a
//! positive first word. In contrast, the established `mbrtowc` UTF-8 partial
//! states have the high bit set, so the two source state machines remain
//! distinguishable without consuming the public second opaque word.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C uchar stateful providers require little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU32, Ordering};

use super::errno;
use super::locale_multibyte::MbState;

// Keep musl's two helper edges as explicit C ABI calls. This names the source
// ownership boundary even when static compilation lowers the public mbrtowc
// façade into its already-owned private decoder helper; this leaf neither
// owns nor reimplements that decoder, encoder, locale selection, or errno.
extern "C" {
    fn mbrtowc(
        wide: *mut c_int,
        source: *const c_char,
        count: usize,
        state: *mut MbState,
    ) -> usize;
    fn wcrtomb(destination: *mut c_char, wide: c_int, state: *mut MbState) -> usize;
}

const EILSEQ: c_int = 84;
const MB_RET_ILSEQ: usize = usize::MAX;
const MB_RET_PENDING_LOW: usize = usize::MAX - 2;

// Musl intentionally gives each C11 entry its own static fallback state. Do
// not merge these with each other or with mbrtowc's separately owned null
// state: a null `ps` selects the per-function static object. Match the
// existing mbrtowc null-state treatment with atomics, which eliminates a Rust
// data race without promising a shared concurrent conversion sequence.
static C16RTOMB_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);
static MBRTOC16_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);
static MBRTOC32_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);

static EMPTY_SOURCE: [u8; 1] = [0];

#[inline]
unsafe fn first_word(state: *const MbState) -> u32 {
    // SAFETY: callers of the public ABI provide live, aligned `mbstate_t`
    // storage whenever the pointer is non-null. Every selected state machine
    // uses only that first word, exactly as musl does.
    unsafe { core::ptr::read(state.cast::<u32>()) }
}

#[inline]
unsafe fn set_first_word(state: *mut MbState, value: u32) {
    // SAFETY: same first-word-only storage contract as `first_word`.
    unsafe { core::ptr::write(state.cast::<u32>(), value) };
}

#[inline]
unsafe fn load_first_word_or_internal(state: *const MbState, internal: &AtomicU32) -> u32 {
    if state.is_null() {
        internal.load(Ordering::Acquire)
    } else {
        // SAFETY: the public caller supplied readable mbstate_t storage.
        unsafe { first_word(state) }
    }
}

#[inline]
unsafe fn store_first_word_or_internal(
    state: *mut MbState,
    internal: &AtomicU32,
    value: u32,
) {
    if state.is_null() {
        internal.store(value, Ordering::Release);
    } else {
        // SAFETY: the public caller supplied writable mbstate_t storage.
        unsafe { set_first_word(state, value) };
    }
}

// A null mbrtoc16/mbrtoc32 state must retain the function's own atomic word,
// but the established mbrtowc ABI takes an mbstate_t pointer. This local
// bridge is exactly that public two-u32 layout; mbrtowc observes and updates
// only word zero, after which it is published back to the selected atomic.
#[repr(C)]
struct InternalStateBridge {
    opaque1: u32,
    _opaque2: u32,
}

#[inline]
unsafe fn mbrtowc_with_selected_state(
    wide: *mut c_int,
    source: *const c_char,
    count: usize,
    state: *mut MbState,
    internal: &AtomicU32,
) -> usize {
    if state.is_null() {
        let mut bridge = InternalStateBridge {
            opaque1: internal.load(Ordering::Acquire),
            _opaque2: 0,
        };
        // SAFETY: the bridge has the public x86 mbstate_t size/alignment and
        // mbrtowc's established contract touches only its first u32.
        let result = unsafe {
            mbrtowc(
                wide,
                source,
                count,
                (&mut bridge as *mut InternalStateBridge).cast::<MbState>(),
            )
        };
        internal.store(bridge.opaque1, Ordering::Release);
        result
    } else {
        // SAFETY: forwards the caller's public mbrtowc pointer contract.
        unsafe { mbrtowc(wide, source, count, state) }
    }
}

/// Convert one UTF-16 code unit through musl's pending-surrogate state.
///
/// `destination`, when non-null, must point to writable storage for the
/// selected multibyte output (at most four bytes); `state`, when non-null,
/// must point to initialized, live, aligned x86 `mbstate_t` storage that is
/// readable and writable for this call. The C ABI reads and writes only that
/// storage's first u32. Callers serialize use of a shared state; a null state
/// selects this entry's atomic fallback, whose calls likewise need external
/// serialization to form one coherent conversion sequence. A null destination
/// is musl's reset query: it reports a pending high surrogate as EILSEQ and
/// clears it.
#[no_mangle]
pub unsafe extern "C" fn c16rtomb(
    destination: *mut c_char,
    c16: u16,
    state: *mut MbState,
) -> usize {
    // SAFETY: a non-null state is caller-owned live mbstate_t storage; null
    // selects c16rtomb's separate atomic fallback word.
    let pending = unsafe { load_first_word_or_internal(state, &C16RTOMB_INTERNAL_STATE) };

    if destination.is_null() {
        if pending != 0 {
            // SAFETY: same selected first-word state contract as above.
            unsafe { store_first_word_or_internal(state, &C16RTOMB_INTERNAL_STATE, 0) };
            // SAFETY: the musl error belongs to this calling C thread.
            unsafe { errno::set_errno(EILSEQ) };
            return MB_RET_ILSEQ;
        }
        return 1;
    }

    let c16 = u32::from(c16);
    if pending == 0 && c16.wrapping_sub(0xd800) < 0x400 {
        // Store `(high - 0xd7c0) << 10`, so the subsequent low-surrogate
        // branch can use musl's one-addition scalar reconstruction.
        // SAFETY: same selected first-word state contract as above.
        unsafe {
            store_first_word_or_internal(
                state,
                &C16RTOMB_INTERNAL_STATE,
                c16.wrapping_sub(0xd7c0) << 10,
            )
        };
        return 0;
    }

    let wide = if pending != 0 {
        if c16.wrapping_sub(0xdc00) >= 0x400 {
            // SAFETY: the invalid continuation clears only selected word zero.
            unsafe { store_first_word_or_internal(state, &C16RTOMB_INTERNAL_STATE, 0) };
            // SAFETY: publish musl's C conversion error in the existing TLS.
            unsafe { errno::set_errno(EILSEQ) };
            return MB_RET_ILSEQ;
        }
        // SAFETY: a completed pair transitions back to the initial state
        // before wcrtomb is called, matching the source ordering.
        unsafe { store_first_word_or_internal(state, &C16RTOMB_INTERNAL_STATE, 0) };
        pending.wrapping_add(c16).wrapping_sub(0xdc00)
    } else {
        c16
    };

    // Musl does not forward c16rtomb's state to the stateless selected output
    // conversion. wcrtomb owns scalar/profile validation and stale errno on
    // every successful return.
    unsafe { wcrtomb(destination, wide as c_int, core::ptr::null_mut()) }
}

/// Decode one C multibyte sequence into a UTF-16 code unit.
///
/// `source` must be null or readable for `count` bytes; `output`, when
/// non-null, must point to writable `char16_t` storage; and `state`, when
/// non-null, must name initialized, live, aligned x86 `mbstate_t` storage that
/// is readable and writable for this call. Callers serialize use of a shared
/// state; null-state calls choose this entry's atomic fallback and likewise
/// need external serialization for one coherent conversion sequence. Pending
/// UTF-16 low-surrogate state returns `(size_t)-3` without inspecting `source`,
/// while high-bit-set decoder state is delegated to the established mbrtowc
/// owner.
#[no_mangle]
pub unsafe extern "C" fn mbrtoc16(
    output: *mut u16,
    source: *const c_char,
    count: usize,
    state: *mut MbState,
) -> usize {
    if source.is_null() {
        // Pinned musl recursively supplies one empty NUL byte. This preserves
        // both the pending-low-surrogate `-3` branch and an incomplete UTF-8
        // state's ordinary mbrtowc error/reset behavior.
        return unsafe {
            mbrtoc16(
                core::ptr::null_mut(),
                EMPTY_SOURCE.as_ptr().cast::<c_char>(),
                1,
                state,
            )
        };
    }

    // SAFETY: a non-null state is caller-owned storage; null chooses the
    // independent mbrtoc16 atomic fallback.
    let pending = unsafe { load_first_word_or_internal(state, &MBRTOC16_INTERNAL_STATE) };
    if (pending as c_int) > 0 {
        if !output.is_null() {
            // SAFETY: the C caller supplied writable char16_t storage.
            unsafe { core::ptr::write(output, pending as u16) };
        }
        // SAFETY: emitting the saved low surrogate consumes only selected word zero.
        unsafe { store_first_word_or_internal(state, &MBRTOC16_INTERNAL_STATE, 0) };
        return MB_RET_PENDING_LOW;
    }

    let mut wide: c_int = 0;
    // SAFETY: forwards the caller's source/count through either the caller
    // state or the local bridge for mbrtoc16's selected atomic null state.
    let result = unsafe {
        mbrtowc_with_selected_state(
            &mut wide,
            source,
            count,
            state,
            &MBRTOC16_INTERNAL_STATE,
        )
    };
    if result <= 4 {
        let mut value = wide as u32;
        if value >= 0x1_0000 {
            // Store the low half as a positive first word; mbrtowc's partial
            // UTF-8 states always have their high bit set.
            // SAFETY: state remains valid and only selected word zero changes.
            unsafe {
                store_first_word_or_internal(
                    state,
                    &MBRTOC16_INTERNAL_STATE,
                    (value & 0x3ff).wrapping_add(0xdc00),
                )
            };
            value = 0xd7c0u32.wrapping_add(value >> 10);
        }
        if !output.is_null() {
            // SAFETY: the C caller supplied writable char16_t storage.
            unsafe { core::ptr::write(output, value as u16) };
        }
    }
    result
}

/// Decode one C multibyte sequence into a UTF-32 code point.
///
/// `source` must be null or readable for `count` bytes; `output`, when
/// non-null, must point to writable `char32_t` storage; and `state`, when
/// non-null, must name initialized, live, aligned x86 `mbstate_t` storage that
/// is readable and writable for this call. Callers serialize use of a shared
/// state; null-state calls choose this entry's atomic fallback and likewise
/// need external serialization for one coherent conversion sequence. A null
/// source is routed through a one-byte empty string exactly as in musl.
#[no_mangle]
pub unsafe extern "C" fn mbrtoc32(
    output: *mut u32,
    source: *const c_char,
    count: usize,
    state: *mut MbState,
) -> usize {
    if source.is_null() {
        // Preserve mbrtowc's normal NUL conversion and its incomplete-state
        // reset/error path instead of treating a null source as an ad hoc
        // state clear.
        return unsafe {
            mbrtoc32(
                core::ptr::null_mut(),
                EMPTY_SOURCE.as_ptr().cast::<c_char>(),
                1,
                state,
            )
        };
    }

    let mut wide: c_int = 0;
    // SAFETY: forwards through either the caller state or mbrtoc32's own
    // atomic fallback bridge without sharing mbrtoc16/mbrtowc null state.
    let result = unsafe {
        mbrtowc_with_selected_state(
            &mut wide,
            source,
            count,
            state,
            &MBRTOC32_INTERNAL_STATE,
        )
    };
    if result <= 4 && !output.is_null() {
        // SAFETY: x86 char32_t is a four-byte unsigned scalar storage slot.
        unsafe { core::ptr::write(output, wide as u32) };
    }
    result
}
