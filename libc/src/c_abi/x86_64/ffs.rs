//! Selected static Linux/x86-64 find-first-set C ABI.
//!
//! This leaf owns exactly `ffs`, `ffsl`, and `ffsll`: each returns one plus
//! the index of its least-significant set bit, or zero for a zero input. It is
//! scalar, stateless, allocation-free, and has no syscall, errno, TLS,
//! locale, cancellation, mutable-global-state, pointer, or callback boundary.
//! It is not general bit operations, `fls`, C string manipulation, integer
//! parsing, atomics, floating-point math, stdio, libc.so, a CRT, a loader, a
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/misc/ffs.c` maps to `ffs` below.
//! - `src/misc/ffsl.c` maps to `ffsl` below.
//! - `src/misc/ffsll.c` maps to `ffsll` below.
//! - Those musl leaves call `a_ctz_l`/`a_ctz_64` from
//!   `src/internal/atomic.h` (with the x86-64 atomic-architecture helper).
//!   This isolated Rust translation uses only the equivalent concrete-width
//!   scalar count, so it does not import musl's broad atomic machinery.
//!
//! Linux/x86-64 is two's-complement LP64: `int` is 32-bit while `long` and
//! `long long` are 64-bit. Casting negative inputs to those unsigned widths
//! preserves their input bit patterns, matching musl's ctz helper path. The
//! explicit zero branch mirrors musl's source guard before `a_ctz_*`; it also
//! keeps zero's specified result separate from the nonzero count operation.

use core::ffi::{c_int, c_long, c_longlong};

/// Return one plus the least-significant set-bit index in a nonzero `u32`.
#[inline]
fn first_set_u32(value: u32) -> c_int {
    if value == 0 {
        0
    } else {
        value.trailing_zeros() as c_int + 1
    }
}

/// Return one plus the least-significant set-bit index in a nonzero `u64`.
#[inline]
fn first_set_u64(value: u64) -> c_int {
    if value == 0 {
        0
    } else {
        value.trailing_zeros() as c_int + 1
    }
}

/// Return the one-based least-significant set-bit position in a C `int`.
#[no_mangle]
pub extern "C" fn ffs(value: c_int) -> c_int {
    first_set_u32(value as u32)
}

/// Return the one-based least-significant set-bit position in a C `long`.
#[no_mangle]
pub extern "C" fn ffsl(value: c_long) -> c_int {
    first_set_u64(value as u64)
}

/// Return the one-based least-significant set-bit position in C `long long`.
#[no_mangle]
pub extern "C" fn ffsll(value: c_longlong) -> c_int {
    first_set_u64(value as u64)
}
