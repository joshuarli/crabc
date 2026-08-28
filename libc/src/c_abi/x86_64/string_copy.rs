//! Selected static Linux/x86-64 C C-string copy and concatenation boundary.
//!
//! This leaf owns exactly one stateless, allocation-free C-string mutation
//! block: `stpcpy`, `stpncpy`, `strcpy`, `strncpy`, `strcat`, `strncat`,
//! `strlcpy`, and `strlcat`. It has no syscall, `errno`, TLS, allocator,
//! locale, cancellation, or mutable global-state boundary. It is not bounded
//! byte transfer, duplication/allocation, tokenization, case folding, locale
//! collation, path mutation, stdio, libc.so, a CRT, pthread/TLS lifecycle,
//! dynamic TLS, a loader, a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/stpcpy.c` maps to `stpcpy` and the private copy-to-NUL helper
//!   below. Musl names that helper `__stpcpy` and weak-aliases it publicly;
//!   this closed archive keeps `__stpcpy` private and unexported.
//! - `src/string/stpncpy.c` maps to `stpncpy` and the private padded-copy
//!   helper below. Its musl `__stpncpy` helper is likewise not exported here.
//! - `src/string/strcpy.c`, `src/string/strncpy.c`, `src/string/strcat.c`,
//!   `src/string/strncat.c`, `src/string/strlcpy.c`, and
//!   `src/string/strlcat.c` map respectively to the named public entries.
//!
//! The pinned sources use optional `__GNUC__` word-copy paths. This leaf keeps
//! their scalar fallback behavior: every raw read/write is one proven byte of
//! the caller's exact C-string or bounded range, including when a terminator
//! is placed at a protected-page edge. The local helpers also avoid pulling a
//! neighboring public string object into this freestanding artifact.

use core::ffi::c_char;

/// Copy a complete C string and return the destination terminator position.
///
/// # Safety
///
/// `destination` must be writable through the terminating NUL of `source`.
/// `source` must designate a readable NUL-terminated byte sequence, and the
/// source and destination ranges must not overlap.
#[inline]
unsafe fn copy_c_string(mut destination: *mut u8, mut source: *const u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract supplies the current C-string source
        // byte and the corresponding writable destination byte.
        let byte = unsafe { source.read() };
        // SAFETY: the same contract makes this one destination write valid.
        unsafe { destination.write(byte) };
        if byte == 0 {
            return destination;
        }
        // SAFETY: the observed source byte was non-NUL, so the C-string
        // contract supplies its next byte.
        source = unsafe { source.add(1) };
        // SAFETY: the destination capacity covers the next copied byte.
        destination = unsafe { destination.add(1) };
    }
}

/// Copy at most `count` source bytes and zero-fill the remaining destination.
///
/// The return is the first destination NUL when source ends early, otherwise
/// the one-past-final destination byte, exactly matching musl `__stpncpy`.
///
/// # Safety
///
/// `destination` must designate `count` writable bytes. If `count` is
/// nonzero, `source` must designate readable bytes through either its first
/// NUL or `count` bytes. The source and destination ranges must not overlap;
/// both pointers may be null only when `count` is zero.
#[inline]
unsafe fn copy_n_padded(
    mut destination: *mut u8,
    mut source: *const u8,
    mut count: usize,
) -> *mut u8 {
    while count != 0 {
        // SAFETY: the retained count supplies this current source byte.
        let byte = unsafe { source.read() };
        if byte == 0 {
            let terminator = destination;
            while count != 0 {
                // SAFETY: every remaining iteration writes one byte of the
                // caller-provided exact destination range.
                unsafe { destination.write(0) };
                // SAFETY: this advances only to the following or one-past
                // byte of that exact destination range.
                destination = unsafe { destination.add(1) };
                count = count.wrapping_sub(1);
            }
            return terminator;
        }
        // SAFETY: the helper retains a writable destination byte here.
        unsafe { destination.write(byte) };
        // SAFETY: the copied source byte was non-NUL, so another bounded byte
        // is required only if a later iteration retains a nonzero count.
        source = unsafe { source.add(1) };
        // SAFETY: the exact destination range has a following or one-past
        // pointer after consuming this copied byte.
        destination = unsafe { destination.add(1) };
        count = count.wrapping_sub(1);
    }
    destination
}

/// Return the location of a caller-owned C-string terminator.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn c_string_end(mut string: *mut u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract supplies each current C-string byte.
        if unsafe { string.read() } == 0 {
            return string;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        string = unsafe { string.add(1) };
    }
}

/// Measure one caller-owned C string with byte-at-a-time reads.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn c_string_length(mut string: *const u8) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: the helper contract supplies each current C-string byte.
        if unsafe { string.read() } == 0 {
            return length;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        string = unsafe { string.add(1) };
        length = length.wrapping_add(1);
    }
}

/// Measure at most `limit` readable bytes before a C-string terminator.
///
/// # Safety
///
/// If `limit` is nonzero, `string` must designate at least `limit` readable
/// bytes. A null pointer is permitted only with a zero limit.
#[inline]
unsafe fn bounded_c_string_length(mut string: *mut u8, mut limit: usize) -> usize {
    let mut length = 0usize;
    while limit != 0 {
        // SAFETY: the retained limit proves this current byte is readable.
        if unsafe { string.read() } == 0 {
            return length;
        }
        // SAFETY: consuming this byte advances only through the exact bounded
        // range or to its one-past pointer.
        string = unsafe { string.add(1) };
        length = length.wrapping_add(1);
        limit = limit.wrapping_sub(1);
    }
    length
}

/// Musl-shaped `strlcpy` core that returns the complete source length.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated byte sequence. If
/// `capacity` is nonzero, `destination` must designate `capacity` writable
/// bytes. The source and destination ranges must not overlap; destination may
/// be null only with zero capacity.
#[inline]
unsafe fn copy_with_limit(
    mut destination: *mut u8,
    mut source: *const u8,
    capacity: usize,
) -> usize {
    let mut source_length = 0usize;
    if capacity != 0 {
        let mut remaining = capacity.wrapping_sub(1);
        while remaining != 0 {
            // SAFETY: the source C-string contract supplies this byte.
            let byte = unsafe { source.read() };
            if byte == 0 {
                // SAFETY: capacity is nonzero, so the current destination
                // slot remains inside the exact caller-owned output range.
                unsafe { destination.write(0) };
                return source_length;
            }
            // SAFETY: remaining reserves this output slot before its NUL.
            unsafe { destination.write(byte) };
            // SAFETY: non-NUL source input has a following C-string byte.
            source = unsafe { source.add(1) };
            // SAFETY: the following output slot remains within the reserved
            // capacity or is the final terminator position.
            destination = unsafe { destination.add(1) };
            source_length = source_length.wrapping_add(1);
            remaining = remaining.wrapping_sub(1);
        }
        // SAFETY: this is the final reserved byte of the nonzero output range.
        unsafe { destination.write(0) };
    }

    loop {
        // SAFETY: the source C-string contract supplies this continuation byte.
        if unsafe { source.read() } == 0 {
            return source_length;
        }
        // SAFETY: a non-NUL source byte proves the following one exists.
        source = unsafe { source.add(1) };
        source_length = source_length.wrapping_add(1);
    }
}

/// Copy a C string and return the destination terminator position.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string, `destination`
/// must be writable through that terminator, and the two ranges must not
/// overlap. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn stpcpy(
    destination: *mut c_char,
    source: *const c_char,
) -> *mut c_char {
    // SAFETY: the public C-string and non-overlap contract is the private
    // helper's exact contract after spelling C `char` as its raw byte storage.
    unsafe { copy_c_string(destination.cast::<u8>(), source.cast::<u8>()) }
        .cast::<c_char>()
}

/// Copy at most `count` bytes and return the copied terminator or end pointer.
///
/// # Safety
///
/// `destination` must designate `count` writable bytes. If `count` is
/// nonzero, `source` must designate readable bytes through either its first
/// NUL or `count` bytes. The two ranges must not overlap; both pointers may be
/// null only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn stpncpy(
    destination: *mut c_char,
    source: *const c_char,
    count: usize,
) -> *mut c_char {
    // SAFETY: the public bounded-copy and non-overlap contract maps directly
    // to the private musl-shaped padded-copy helper.
    unsafe { copy_n_padded(destination.cast::<u8>(), source.cast::<u8>(), count) }
        .cast::<c_char>()
}

/// Copy one complete C string and return its destination start pointer.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string, `destination`
/// must be writable through that terminator, and the two ranges must not
/// overlap. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcpy(
    destination: *mut c_char,
    source: *const c_char,
) -> *mut c_char {
    // SAFETY: this has exactly the internal C-string-copy contract.
    unsafe { copy_c_string(destination.cast::<u8>(), source.cast::<u8>()) };
    destination
}

/// Copy at most `count` bytes, zero-filling any remaining destination bytes.
///
/// # Safety
///
/// `destination` must designate `count` writable bytes. If `count` is
/// nonzero, `source` must designate readable bytes through either its first
/// NUL or `count` bytes. The two ranges must not overlap; both pointers may be
/// null only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn strncpy(
    destination: *mut c_char,
    source: *const c_char,
    count: usize,
) -> *mut c_char {
    // SAFETY: this has exactly the internal bounded padded-copy contract.
    unsafe { copy_n_padded(destination.cast::<u8>(), source.cast::<u8>(), count) };
    destination
}

/// Append one complete C string and return the destination start pointer.
///
/// # Safety
///
/// `destination` must designate a readable NUL-terminated C string followed
/// by writable capacity for every source byte and one new terminator. `source`
/// must designate a readable NUL-terminated C string, and the ranges must not
/// overlap. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcat(
    destination: *mut c_char,
    source: *const c_char,
) -> *mut c_char {
    // SAFETY: the public destination C-string contract supplies its writable
    // terminator slot, where the private full-string copy begins.
    let end = unsafe { c_string_end(destination.cast::<u8>()) };
    // SAFETY: the public appended-capacity and non-overlap obligations are
    // exactly the helper's C-string-copy contract at that terminator.
    unsafe { copy_c_string(end, source.cast::<u8>()) };
    destination
}

/// Append at most `count` non-NUL source bytes and always write a terminator.
///
/// # Safety
///
/// `destination` must designate a readable NUL-terminated C string followed
/// by writable capacity for the appended prefix and one terminator. If `count`
/// is nonzero, `source` must designate readable bytes through either its first
/// NUL or `count` bytes. The ranges must not overlap; source may be null only
/// when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn strncat(
    destination: *mut c_char,
    source: *const c_char,
    mut count: usize,
) -> *mut c_char {
    // SAFETY: the public destination C-string contract supplies its writable
    // terminator slot for the first append byte or replacement terminator.
    let mut output = unsafe { c_string_end(destination.cast::<u8>()) };
    let mut input = source.cast::<u8>();
    while count != 0 {
        // SAFETY: the public bounded-source contract supplies this input byte.
        let byte = unsafe { input.read() };
        if byte == 0 {
            break;
        }
        // SAFETY: the public appended-capacity contract supplies this output.
        unsafe { output.write(byte) };
        // SAFETY: a non-NUL source byte has a following bounded byte whenever
        // a later iteration retains a nonzero count.
        input = unsafe { input.add(1) };
        // SAFETY: the output capacity supplies this following terminator slot.
        output = unsafe { output.add(1) };
        count = count.wrapping_sub(1);
    }
    // SAFETY: the public output-capacity contract reserves the final NUL slot,
    // including the original terminator when no source byte is appended.
    unsafe { output.write(0) };
    destination
}

/// Copy into at most `capacity` destination bytes and return source length.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string. If `capacity`
/// is nonzero, `destination` must designate `capacity` writable bytes. The
/// ranges must not overlap; destination may be null only when capacity is
/// zero.
#[no_mangle]
pub unsafe extern "C" fn strlcpy(
    destination: *mut c_char,
    source: *const c_char,
    capacity: usize,
) -> usize {
    // SAFETY: the public source/output/non-overlap contract maps directly to
    // the private musl-shaped bounded-copy core.
    unsafe { copy_with_limit(destination.cast::<u8>(), source.cast::<u8>(), capacity) }
}

/// Append within at most `capacity` destination bytes and return attempted size.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string. If `capacity`
/// is nonzero, `destination` must designate `capacity` readable and writable
/// bytes; it may lack a NUL in that bounded range. The ranges must not overlap;
/// destination may be null only when capacity is zero.
#[no_mangle]
pub unsafe extern "C" fn strlcat(
    destination: *mut c_char,
    source: *const c_char,
    capacity: usize,
) -> usize {
    // SAFETY: the public bounded destination contract is exactly this private
    // bounded-length helper's contract.
    let destination_length = unsafe { bounded_c_string_length(destination.cast::<u8>(), capacity) };
    if destination_length == capacity {
        // SAFETY: the public source C-string contract retains the full scan;
        // zero capacity never examines the destination pointer.
        return capacity.wrapping_add(unsafe { c_string_length(source.cast::<u8>()) });
    }
    // SAFETY: destination_length is inside the nonzero bounded output object,
    // at its observed terminator, so this starts the available append suffix.
    let append_start = unsafe { destination.cast::<u8>().add(destination_length) };
    // SAFETY: the remaining capacity is nonzero and the public output/source
    // contracts retain this private bounded copy at the terminator.
    let source_length = unsafe {
        copy_with_limit(
            append_start,
            source.cast::<u8>(),
            capacity.wrapping_sub(destination_length),
        )
    };
    destination_length.wrapping_add(source_length)
}
