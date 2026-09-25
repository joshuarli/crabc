//! Bounded wide-string conversion and duplication for the owned x86 runtime.
//!
//! Semantic source: musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT `COPYRIGHT`:
//! `src/multibyte/mbsnrtowcs.c` maps to `mbsnrtowcs`/`decode_bounded`,
//! `src/multibyte/wcsnrtombs.c` maps to `wcsnrtombs`, and
//! `src/string/wcsdup.c` maps to `wcsdup`. The existing multibyte leaf owns
//! decoding, encoding, locale selection, and opaque-state representation.
//! The existing wide-string leaf owns length/copy operations. Duplication
//! uses the selected C malloc provider and returns storage for ordinary free.
//!
//! Null-destination counting retains the source's asymmetric state behavior:
//! mbsnrtowcs can update its conversion state without updating the caller's
//! source pointer, while wcsnrtombs ignores its state argument altogether.
//! Incomplete byte sequences consume the available input and retain a pending
//! state; malformed input returns EILSEQ at the first unconverted sequence.

use core::{ffi::{c_char, c_int, c_void}, ptr};
use core::sync::atomic::{AtomicU32, Ordering};
use super::{locale_multibyte, wide_character};
use locale_multibyte::MbState;

unsafe extern "C" { fn malloc(bytes: usize) -> *mut c_void; }

// Musl's mbsnrtowcs owns one static unsigned state, distinct from mbrtowc's.
// Follow the existing conversion leaves' atomic storage convention to avoid
// a Rust data race without promising one meaningful concurrent sequence.
static DECODE_INTERNAL_STATE: AtomicU32 = AtomicU32::new(0);

unsafe fn decode_bounded(destination: *mut c_int, source: *mut *const c_char,
    mut bytes: usize, mut capacity: usize, state: *mut MbState) -> usize {
    unsafe {
        let mut count = 0usize;
        let mut cursor = source.read();
        let mut scratch = [0 as c_int; 256];
        let mut output = if destination.is_null() {
            capacity = scratch.len();
            scratch.as_mut_ptr()
        } else { destination };

        // Source optimization: at most bytes/4 output slots keep the shared
        // mbsrtowcs kernel within this call's bounded byte extent.
        while !cursor.is_null() && capacity != 0 {
            let mut chunk = bytes / 4;
            if chunk < capacity && chunk <= 32 { break; }
            if chunk >= capacity { chunk = capacity; }
            let before = cursor;
            let pending = state.cast::<u32>().read() != 0;
            let converted = locale_multibyte::mbsrtowcs(output, &mut cursor, chunk, state);
            if converted == usize::MAX {
                // musl mbsrtowcs.c::resume backs up one byte if the saved
                // partial character fails before it can complete. The frozen
                // helper leaves this pending-error cursor detail unselected;
                // restore it at this owned caller's newly selected boundary.
                // No byte is read through the adjusted diagnostic pointer.
                if pending && cursor == before { cursor = cursor.wrapping_sub(1); }
                count = converted;
                capacity = 0;
                break;
            }
            if !destination.is_null() {
                output = output.add(converted);
                capacity -= converted;
            }
            bytes = if cursor.is_null() { 0 } else { bytes - cursor.offset_from(before) as usize };
            count += converted;
        }
        if !cursor.is_null() {
            while capacity != 0 && bytes != 0 {
                let converted = locale_multibyte::mbrtowc(output, cursor, bytes, state);
                if converted == usize::MAX {
                    count = converted;
                    break;
                }
                if converted == 0 {
                    cursor = ptr::null();
                    break;
                }
                if converted == usize::MAX - 1 {
                    cursor = cursor.add(bytes);
                    break;
                }
                cursor = cursor.add(converted);
                bytes -= converted;
                // The bulk threshold leaves at most 131 bytes for the
                // count-only tail, within the 256-element scratch array.
                output = output.add(1);
                capacity -= 1;
                count += 1;
            }
        }
        if !destination.is_null() { source.write(cursor); }
        count
    }
}

// Musl's `src/multibyte/mbsnrtowcs.c` object.
static_archive_member! { mbsnrtowcs_source {
    /// Convert at most `bytes` input bytes into at most `capacity` wide elements.
    ///
    /// # Safety
    /// `source` must be a live readable pointer object, writable when `destination`
    /// is non-null. `*source` may be null; otherwise it must provide `bytes`
    /// readable bytes or an earlier terminating NUL. A non-null `destination`
    /// must provide `capacity` writable aligned c_int elements. Source, output,
    /// and state storage must not overlap. Non-null `state` must be an initialized
    /// writable mbstate_t for this conversion sequence, without concurrent use.
    /// Null `state` selects this function's shared sequence; callers serialize
    /// calls belonging to it. Locale mutation must follow the existing locale
    /// owner's serialization contract. Count-only calls can still change state.
    /// On a bulk resumed-character error, the source cursor follows musl and can
    /// identify the byte immediately before the supplied continuation. Retain the
    /// original backing object before dereferencing or resuming from that cursor.
    #[no_mangle]
    pub unsafe extern "C" fn mbsnrtowcs(destination: *mut c_int, source: *mut *const c_char,
        bytes: usize, capacity: usize, state: *mut MbState) -> usize {
        if !state.is_null() {
            return unsafe { decode_bounded(destination, source, bytes, capacity, state) };
        }
        // Public mbstate_t is two u32 words; the conversion kernel accesses only
        // its first word. Keep the private static word separate from that ABI.
        let mut local = [DECODE_INTERNAL_STATE.load(Ordering::Acquire), 0u32];
        let result = unsafe { decode_bounded(destination, source, bytes, capacity, local.as_mut_ptr().cast()) };
        DECODE_INTERNAL_STATE.store(local[0], Ordering::Release);
        result
    }
}}

// Musl's `src/multibyte/wcsnrtombs.c` object.
static_archive_member! { wcsnrtombs_source {
    /// Convert at most `characters` wide elements into at most `capacity` bytes.
    ///
    /// # Safety
    /// `source` must be a live readable pointer object, writable when `destination`
    /// is non-null. `*source` may be null; otherwise it must provide `characters`
    /// readable aligned c_int elements or an earlier terminating wide NUL. A
    /// non-null `destination` must provide `capacity` writable bytes, disjoint from
    /// source storage. The state pointer is ignored, as in musl's stateless output
    /// conversion. Locale mutation follows the existing locale owner's contract.
    #[no_mangle]
    pub unsafe extern "C" fn wcsnrtombs(mut destination: *mut c_char,
        source: *mut *const c_int, mut characters: usize, mut capacity: usize,
        _state: *mut MbState) -> usize {
        unsafe {
            let mut cursor = source.read();
            let mut count = 0usize;
            if destination.is_null() { capacity = 0; }
            while !cursor.is_null() && characters != 0 {
                // The selected C/POSIX/C.UTF-8 profile has MB_LEN_MAX == 4.
                let mut scratch = [0 as c_char; 4];
                let output = if capacity < scratch.len() { scratch.as_mut_ptr() } else { destination };
                let converted = locale_multibyte::wcrtomb(output, cursor.read(), ptr::null_mut());
                if converted == usize::MAX { count = converted; break; }
                if !destination.is_null() {
                    if capacity < scratch.len() {
                        if converted > capacity { break; }
                        ptr::copy_nonoverlapping(scratch.as_ptr(), destination, converted);
                    }
                    destination = destination.add(converted);
                    capacity -= converted;
                }
                if cursor.read() == 0 { cursor = ptr::null(); break; }
                cursor = cursor.add(1);
                characters -= 1;
                count += converted;
            }
            if !destination.is_null() { source.write(cursor); }
            count
        }
    }
}}

// Musl's `src/string/wcsdup.c` object.
static_archive_member! { wcsdup_source {
    /// Duplicate a wide string using the selected C allocation provider.
    ///
    /// # Safety
    /// `source` must be a readable aligned NUL-terminated c_int sequence. The
    /// returned allocation, when non-null, belongs to the caller and must be
    /// released with the runtime's ordinary free; it does not borrow `source`.
    #[no_mangle]
    pub unsafe extern "C" fn wcsdup(source: *const c_int) -> *mut c_int {
        unsafe {
            let count = wide_character::wcslen(source).wrapping_add(1);
            let copy = malloc(count.wrapping_mul(core::mem::size_of::<c_int>())).cast::<c_int>();
            if copy.is_null() { return copy; }
            wide_character::wmemcpy(copy, source, count)
        }
    }
}}
