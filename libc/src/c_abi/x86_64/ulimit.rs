//! Selected static Linux/x86-64 `ulimit` C ABI boundary.
//!
//! This private compatibility leaf owns exactly the historical variadic
//! `long ulimit(int command, ...)` spelling. It queries only
//! `RLIMIT_FSIZE=1`; `UL_SETFSIZE=2` alone consumes the first `long` vararg,
//! scales it by musl's `512ULL` byte block, and replaces only that soft limit.
//! Every other command follows musl's query path without reading an absent
//! vararg or manufacturing an error. This is not a general resource API,
//! process-limit policy, file-size policy, or resource-capability claim.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/legacy/ulimit.c` maps to the assembly public boundary plus the two
//! fixed helpers below. Its `getrlimit`/`setrlimit` calls reduce on Linux 5.10
//! x86-64 to `prlimit64=302` for process zero and `RLIMIT_FSIZE`; the musl
//! pre-baseline fallback and pthread `__synccall` path are intentionally not
//! selected. LP64's `rlim_t` already matches the kernel's two unsigned words,
//! so its infinity conversion is a no-op here.
//!
//! SysV AMD64 places the `int` command in edi and, when command two actually
//! supplies it, the promoted `long` vararg in rsi; the `long` result returns in
//! rax. Linux instead receives pid/resource/new-limit/old-limit in
//! rdi/rsi/rdx/r10. Only raw Linux `-4095..=-1` results publish the selected
//! initial-TLS `errno`. A successful query or set preserves stale `errno`.
//! The limit mutation is process-wide and callers retain authority,
//! synchronization, and restoration obligations. This leaf selects no public
//! `getrlimit`/`setrlimit`/`prlimit`, `getrusage`, priority, scheduler,
//! accounting, descriptor, filesystem, pthread, CRT, loader, or public x86
//! support boundary.

use core::ffi::{c_int, c_long};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const RLIMIT_FSIZE: c_int = 1;
const UL_SETFSIZE: c_int = 2;
const BLOCK_BYTES: u64 = 512;

/// The exact x86 LP64 kernel/public rlimit payload used only by this leaf.
#[repr(C)]
struct Rlimit {
    current: u64,
    maximum: u64,
}

const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(size_of::<c_long>() == 8);
    assert!(size_of::<Rlimit>() == 16);
    assert!(align_of::<Rlimit>() == 8);
    assert!(offset_of!(Rlimit, current) == 0);
    assert!(offset_of!(Rlimit, maximum) == 8);
};

/*
 * Rust has no stable C-variadic implementation surface. Keep the public
 * spelling in assembly so a legal `ulimit(UL_GETFSIZE)` call never enters a
 * fixed Rust function that would require rsi. Only UL_SETFSIZE is permitted
 * to preserve rsi into the three-word helper; all other command values take
 * musl's no-vararg query route and deliberately ignore rsi.
 */
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global ulimit
    .type ulimit,@function
ulimit:
    cmp edi, 2
    je {set_limit}
    jmp {query_limit}
    .size ulimit, .-ulimit

    .section .note.GNU-stack,"",@progbits
"#,
    set_limit = sym ulimit_set,
    query_limit = sym ulimit_query,
);

/// Query the calling process's file-size limit through Linux `prlimit64`.
///
/// The local record has the exact x86 `struct rlimit` layout. Linux validates
/// the fixed resource number and writable record before `c_status` translates
/// a raw error; no public resource C entry is selected.
unsafe fn query_fsize_limit(limit: *mut Rlimit) -> c_int {
    // SAFETY: the caller supplies one writable local 16-byte rlimit record;
    // Linux x86-64 receives old_limit in r10 for pid zero/resource one.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(RLIMIT_FSIZE),
            0,
            limit as usize as i64,
        )
    };
    c_status(result)
}

/// Replace the calling process's file-size limit through Linux `prlimit64`.
unsafe fn set_fsize_limit(limit: *const Rlimit) -> c_int {
    // SAFETY: the caller supplies one readable local 16-byte rlimit record;
    // Linux x86-64 receives new_limit in rdx and a null old_limit in r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(RLIMIT_FSIZE),
            limit as usize as i64,
            0,
        )
    };
    c_status(result)
}

/// Handle every no-vararg `ulimit` command as musl's limit query.
#[inline(never)]
extern "C" fn ulimit_query(_command: c_int) -> c_long {
    let mut limit = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `limit` is a private writable x86 record for this syscall.
    if unsafe { query_fsize_limit(&mut limit) } != 0 {
        return -1;
    }
    (limit.current / BLOCK_BYTES) as c_long
}

/// Consume one supplied `long` only for musl's UL_SETFSIZE command.
#[inline(never)]
extern "C" fn ulimit_set(command: c_int, blocks: c_long) -> c_long {
    if command != UL_SETFSIZE {
        return ulimit_query(command);
    }

    let mut limit = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `limit` is a private writable x86 record for this syscall.
    if unsafe { query_fsize_limit(&mut limit) } != 0 {
        return -1;
    }

    // `512ULL * val` first converts signed long to musl's unsigned rlim_t;
    // wrapping multiplication preserves that exact LP64 C conversion.
    limit.current = (blocks as u64).wrapping_mul(BLOCK_BYTES);
    // SAFETY: `limit` remains a readable local record through this syscall.
    if unsafe { set_fsize_limit(&limit) } != 0 {
        return -1;
    }
    (limit.current / BLOCK_BYTES) as c_long
}
