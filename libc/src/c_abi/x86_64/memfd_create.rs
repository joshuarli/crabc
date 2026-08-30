//! Selected static Linux/x86-64 C `memfd_create(2)` boundary.
//!
//! This leaf owns exactly the GNU C `memfd_create` entry point. It composes
//! Linux's two-word `memfd_create=319` syscall register ABI with the selected
//! initial-TLS C `errno` publisher. It is not a seal or `fcntl` ABI,
//! `memfd_secret`, a descriptor-lifecycle framework, a filesystem policy,
//! libc.so, CRT, dynamic TLS, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/memfd_create.c` maps directly to [`memfd_create`].
//!
//! Musl's source is itself one direct `syscall(SYS_memfd_create, name, flags)`
//! wrapper. Linux therefore owns the complete NUL-terminated label-pointer,
//! 249-byte label, and flag-word contract. In particular, this leaf neither
//! filters unknown flags nor interprets `MFD_ALLOW_SEALING`; the accompanying
//! artifact proves only direct valid-label, overlong-label, invalid-pointer,
//! and invalid-flag behavior. `MFD_HUGETLB` resource and page-size policy,
//! sealing operations, and all `fcntl` commands remain separate work.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

/// Create one anonymous Linux memory-file descriptor.
///
/// # Safety
///
/// `name` is forwarded opaquely to Linux and is never dereferenced by Rust.
/// For success it must identify one readable NUL-terminated byte string for
/// the syscall's duration; null or inaccessible values instead retain Linux's
/// direct error result. Its label bytes and `flags` are likewise Linux's
/// complete `memfd_create(2)` contract. A nonnegative result transfers
/// ownership of a new descriptor to the caller; this narrow C ABI owns neither
/// close nor seals/fcntl behavior.
#[no_mangle]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the raw x86 boundary only places the opaque pointer and flag
    // word in rdi/rsi; Linux validates both before `c_status` publishes its
    // direct error result.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MEMFD_CREATE,
            name as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
