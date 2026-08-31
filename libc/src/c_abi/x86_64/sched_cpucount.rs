//! Selected static Linux/x86-64 GNU `__sched_cpucount` boundary.
//!
//! This leaf counts set bits in exactly `size` readable caller-owned bytes
//! beginning at a `cpu_set_t` pointer. The size and pointer use the System V
//! AMD64 integer registers and the bounded result returns in `eax`. It does
//! not observe or mutate CPU affinity, scheduler policy, CPU topology, thread
//! state, clocks/timers, calendar/timezone/environment state, errno, TLS, or
//! any kernel/runtime path. It is not scheduler support, libc.so, CRT,
//! loader, sysroot, promotion, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/sched/sched_cpucount.c::__sched_cpucount` maps to
//!   [`__sched_cpucount`].
//!
//! Musl casts the supplied `cpu_set_t` to `const unsigned char *`, then visits
//! each selected byte and all eight bit positions. This direct Rust spelling
//! keeps that bytewise source boundary instead of selecting the adjacent
//! affinity syscalls or the broader CPU_* macro family. The valid selected
//! range is the 128-byte `cpu_set_t` public object; a null/unreadable pointer,
//! a size beyond caller-readable storage, and count conversion above `INT_MAX`
//! are outside this artifact's C source contract.

use core::ffi::{c_int, c_void};

/// Count the set bits in `size` caller-owned bytes of a GNU CPU mask.
///
/// The C header gives this private helper the exact
/// `int __sched_cpucount(size_t, const cpu_set_t *)` spelling. Callers must
/// provide a non-null pointer to at least `size` readable bytes; the selected
/// static proof uses sizes through the fixed 128-byte `cpu_set_t` object.
#[no_mangle]
pub unsafe extern "C" fn __sched_cpucount(size: usize, set: *const c_void) -> c_int {
    let bytes = set.cast::<u8>();
    let mut index = 0usize;
    let mut count = 0usize;

    // Musl's nested `size_t i, j` loops inspect each byte before each of its
    // eight bit positions. The `wrapping_add` preserves unsigned-size_t count
    // arithmetic without adding an overflow policy outside the C source.
    while index < size {
        let byte = unsafe { core::ptr::read(bytes.add(index)) };
        let mut bit = 0usize;
        while bit < 8 {
            if byte & (1u8 << bit) != 0 {
                count = count.wrapping_add(1);
            }
            bit = bit.wrapping_add(1);
        }
        index = index.wrapping_add(1);
    }

    count as c_int
}
