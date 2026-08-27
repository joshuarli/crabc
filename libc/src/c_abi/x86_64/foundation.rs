//! Native Linux/x86-64 C-runtime primitive composition.
//!
//! This is a deliberately narrow source-only composition root. It combines
//! the already isolated raw x86 syscall instruction boundary, initial TLS
//! `errno`, and the fixed-musl x86 memory and floating-environment leaves so
//! their ELF linkage can be tested together without selecting `crabc-libc`.
//! In particular, it does **not** relax `libc/src/lib.rs`'s AArch64 target
//! gate, export a complete C runtime artifact, or make any public x86 support
//! claim.
//!
//! The private fixed-six-word bridge below is the target-specific extraction
//! of `libc/src/syscall.rs`'s raw-result-to-errno translation. It deliberately
//! does not export C's `syscall(long, ...)`: a variadic C call carries no
//! reliable argument count, so this source-only primitive object must not
//! pretend it can safely read absent trailing words. A selected full libc must
//! own that public musl-compatible wrapper alongside its complete C ABI. The
//! bridge uses the proved `x86_64/syscall.rs` register implementation and its
//! TLS writer is kept beside x86 `ERRNO`. The child `fenv` and `memory` modules
//! retain their own fixed musl 1.2.6 source mappings and complete focused
//! differential probes. Pthread/clone/TLS lifecycle, public signal behavior,
//! C layouts beyond the named headers, atomics, and every broad C/POSIX family
//! remain separate promotion obligations.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C-runtime foundation requires little-endian Linux/x86-64");

#[path = "errno.rs"]
mod errno;
#[path = "fenv.rs"]
mod fenv;
#[path = "memory.rs"]
mod memory;
#[allow(dead_code)]
#[path = "syscall.rs"]
mod raw_syscall;

use core::ffi::{c_int, c_long};

/// Issue one private fixed-six-word Linux/x86-64 syscall bridge and translate
/// a kernel error through the calling thread's C `errno` slot.
///
/// The uniquely prefixed export exists only for the isolated native evidence
/// fixture. It deliberately makes no pointer-validity, cancellation, restart,
/// signal, public `syscall(long, ...)`, or C/POSIX wrapper claim; those
/// contracts belong to the later selected runtime families. All six `c_long`
/// words are explicit, so no absent variadic argument is ever read.
#[no_mangle]
pub unsafe extern "C" fn crabc_x86_64_foundation_syscall6(
    num: c_long,
    a: c_long,
    b: c_long,
    c: c_long,
    d: c_long,
    e: c_long,
    f: c_long,
) -> c_long {
    // SAFETY: This C entry point forwards the six caller-supplied machine
    // words to the exact raw x86 syscall ABI. Pointer and syscall-specific
    // validity remain the C caller's responsibility at this narrow boundary.
    let result = unsafe {
        raw_syscall::syscall6(
            num as i64,
            a as i64,
            b as i64,
            c as i64,
            d as i64,
            e as i64,
            f as i64,
        )
    };

    if (result as u64) > (-4096_i64 as u64) {
        // SAFETY: A Linux raw result in this range encodes exactly the
        // positive errno number that C's `syscall` wrapper must publish.
        // `wrapping_neg` keeps this no_std source-only object free of a
        // compiler-inserted overflow panic dependency; the preceding Linux
        // errno-range check proves the normal value is one through 4095.
        unsafe { errno::set_errno(result.wrapping_neg() as c_int) };
        return -1;
    }

    result as c_long
}
