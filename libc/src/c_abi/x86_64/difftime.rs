//! Selected static Linux/x86-64 C `difftime` boundary.
//!
//! This leaf owns exactly one scalar conversion: two signed LP64 `time_t`
//! words enter in the integer calling registers and one IEEE-754 binary64
//! result returns in `xmm0`. It performs no clock observation, errno access,
//! syscall, environment read, timezone lookup, calendar conversion, or
//! formatting policy. It is not a C time-family capability, libc.so, CRT,
//! dynamic TLS, loader, sysroot, allocator, promotion, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/time/difftime.c` maps to [`difftime`].
//!
//! Musl spells the body as `return t1-t0;`. For C-defined pairs that signed
//! subtraction is representable in `time_t`, conversion after subtraction is
//! observably different from subtracting two independently rounded binary64
//! operands near an endpoint. `wrapping_sub` retains that target scalar
//! operation without a Rust debug-overflow path; the focused evidence claims
//! only ordinary and non-overflow endpoint-adjacent C input pairs.

use core::ffi::c_long;

/// Return the one bounded C `time_t` difference as IEEE-754 binary64.
///
/// The two signed LP64 C arguments use the System V AMD64 integer registers;
/// the Rust `f64` return uses the binary64 `xmm0` result register. The source
/// C expression has no portable signed-overflow contract, so this artifact
/// does not promote cross-endpoint overflowing inputs into a calendar or time
/// policy.
#[no_mangle]
pub extern "C" fn difftime(left: c_long, right: c_long) -> f64 {
    left.wrapping_sub(right) as f64
}
