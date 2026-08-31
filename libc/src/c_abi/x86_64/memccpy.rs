//! Linux/x86-64 selected static C `memccpy` leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The exact source
//! closure is `src/string/memccpy.c`: its same-alignment word-at-a-time copy
//! uses a target-byte `HASZERO` scan, then falls back to a byte-exact tail so
//! the returned pointer names the byte immediately after the first copied
//! target. The scalar tail also covers mismatched source/destination alignment.
//!
//! This leaf is stateless and allocation-free. It owns no errno, TLS, syscall,
//! locale, allocator, mutable runtime, or other C-memory entry point. It is a
//! private selected static artifact, not `memory.bytes-basic`, general bulk
//! memory, libc.so, a CRT, loader, sysroot, or public x86 support claim.

use core::{
    ffi::{c_int, c_void},
    mem::size_of,
    ptr::null_mut,
};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C memccpy leaf requires little-endian Linux/x86-64");

const WORD_SIZE: usize = size_of::<usize>();
const ALIGN: usize = WORD_SIZE - 1;
const ONES: usize = usize::MAX / u8::MAX as usize;
const HIGHS: usize = ONES * (u8::MAX as usize / 2 + 1);

#[inline]
const fn has_zero_byte(value: usize) -> bool {
    value.wrapping_sub(ONES) & !value & HIGHS != 0
}

/// Copy at most `count` non-overlapping bytes through the first `byte` value.
///
/// # Safety
///
/// `destination` must designate at least `count` writable bytes and `source`
/// must designate at least `count` readable bytes. The ranges must not
/// overlap, matching the C restrict contract. Null pointers are accepted
/// only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn memccpy(
    destination: *mut c_void,
    source: *const c_void,
    byte: c_int,
    mut count: usize,
) -> *mut c_void {
    let mut destination = destination.cast::<u8>();
    let mut source = source.cast::<u8>();
    let target = byte as u8;

    // This preserves musl's aligned-word optimization exactly: only ranges
    // with equal source/destination residues can be advanced to aligned word
    // pointers without changing their relative alignment.
    if (source as usize & ALIGN) == (destination as usize & ALIGN) {
        while (source as usize & ALIGN) != 0 && count != 0 {
            // SAFETY: the caller provides the remaining one-byte source and
            // destination ranges; both pointers advance only after this copy.
            let copied = unsafe { source.read() };
            // SAFETY: paired with the source read above under the C restrict
            // non-overlap contract.
            unsafe { destination.write(copied) };
            if copied == target {
                // SAFETY: the byte just written belongs to the caller's
                // destination range, so its one-past pointer is valid.
                return unsafe { destination.add(1).cast() };
            }
            count -= 1;
            // SAFETY: a nonfinal iteration leaves one in-range following byte.
            source = unsafe { source.add(1) };
            // SAFETY: paired with the source advance above.
            destination = unsafe { destination.add(1) };
        }

        if (source as usize & ALIGN) == 0 {
            let target_word = ONES.wrapping_mul(target as usize);
            let mut word_destination = destination.cast::<usize>();
            let mut word_source = source.cast::<usize>();

            while count >= WORD_SIZE {
                // SAFETY: equal residues plus the loop's alignment test make
                // both word pointers aligned; the count check keeps this read
                // within the caller's exact source range.
                let copied = unsafe { word_source.read() };
                if has_zero_byte(copied ^ target_word) {
                    break;
                }
                // SAFETY: this word contains no target byte, so musl copies
                // it as a whole and the count check keeps the write in range.
                unsafe { word_destination.write(copied) };
                count -= WORD_SIZE;
                // SAFETY: a completed word leaves the next in-range word only
                // when the next loop iteration's count guard permits it.
                word_source = unsafe { word_source.add(1) };
                // SAFETY: paired with the source word advance above.
                word_destination = unsafe { word_destination.add(1) };
            }
            source = word_source.cast::<u8>();
            destination = word_destination.cast::<u8>();
        }
    }

    while count != 0 {
        // SAFETY: the caller provides the remaining one-byte source and
        // destination ranges; both pointers advance only after this copy.
        let copied = unsafe { source.read() };
        // SAFETY: paired with the source read above under the C restrict
        // non-overlap contract.
        unsafe { destination.write(copied) };
        if copied == target {
            // SAFETY: the byte just written belongs to the caller's
            // destination range, so its one-past pointer is valid.
            return unsafe { destination.add(1).cast() };
        }
        count -= 1;
        // SAFETY: a nonfinal iteration leaves one in-range following byte.
        source = unsafe { source.add(1) };
        // SAFETY: paired with the source advance above.
        destination = unsafe { destination.add(1) };
    }

    null_mut()
}
