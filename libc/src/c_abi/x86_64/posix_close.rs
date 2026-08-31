//! Selected static Linux/x86-64 `posix_close` C ABI boundary.
//!
//! This private leaf owns exactly `int posix_close(int, int)`. Pinned musl
//! 1.2.6 maps `src/unistd/posix_close.c::posix_close` to `close(fd)` and
//! deliberately ignores its `flags` word. Musl's adjacent
//! `src/unistd/close.c::close` converts a raw Linux `EINTR` close result to
//! success without retrying, because retry could close a recycled descriptor.
//! This leaf preserves that complete observable mapping through Linux 5.10
//! x86-64 `close=3`, while keeping its one-symbol archive object independent
//! from the broader selected descriptor-I/O block and its cancellation/AIO
//! boundary.
//!
//! The direct syscall is an intentional isolated adaptation: musl's `close`
//! reaches its cancellation and `__aio_close` hooks before the raw syscall,
//! neither of which belongs to this private static artifact. The raw result
//! otherwise uses the selected initial-TLS C `errno` translator, so success
//! preserves stale errno and Linux errors become C `-1` plus errno exactly as
//! the selected direct close sibling does.
//!
//! The System V AMD64 ABI passes the signed `fd` and ignored `flags` int words
//! in `edi` and `esi`, respectively, and returns the signed C status in eax.
//! This leaf selects no generic descriptor I/O, `close` API, descriptor
//! lifetime/ownership policy, cancellation or AIO coordination, filesystem
//! policy, allocator, locale, signal, process, libc.so, CRT, loader, sysroot,
//! family completion, promotion, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

const EINTR: i64 = 4;

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
};

/// Close one descriptor while retaining musl's ignored `flags` spelling.
///
/// The descriptor remains caller-owned. Linux validates its current lifetime;
/// successful close consumes that descriptor identity, and this isolated leaf
/// supplies no cancellation, AIO, descriptor registry, or retry policy.
#[no_mangle]
pub extern "C" fn posix_close(file_descriptor: c_int, _flags: c_int) -> c_int {
    // SAFETY: Linux/x86-64 close=3 consumes the signed descriptor word in rdi.
    // The second public C word is intentionally ignored exactly as musl's
    // posix_close source does; no absent vararg or caller memory is observed.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(file_descriptor))
    };
    if result == -EINTR {
        0
    } else {
        c_status(result)
    }
}
