//! Selected static Linux/x86-64 GNU/BSD `issetugid` C ABI boundary.
//!
//! This private leaf owns exactly the initial secure-execution observation
//! from pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! The upstream source mapping is `src/misc/issetugid.c::issetugid`, whose
//! whole body returns `libc.secure`. The x86 static archive already derives
//! that same immutable initial-startup fact in [`super::startup_security`]:
//! the final AT_SECURE/UID/EUID/GID/EGID records select one cached Boolean
//! before callbacks. This leaf merely exposes that selected fact as musl's
//! `int issetugid(void)` result.
//!
//! The no-argument signed `int` result is zero or one in `eax` under the
//! System V AMD64 ABI. It neither changes nor reinterprets the cache, writes
//! errno, reads credentials directly, or performs a syscall. Before selected
//! startup has installed a valid initial vector, the private cache's existing
//! false default matches musl's zero-initialized `libc.secure` state.
//!
//! This leaf selects no credential mutation or policy, descriptor hygiene,
//! environment lookup, `secure_getenv`, auxv lookup, loader policy, process
//! lifecycle, pthread/TLS lifecycle, allocator, process.globals, family
//! completion, promotion, or public x86 support.

use core::ffi::c_int;

use super::startup_security;

/// Return musl's cached initial secure-execution fact as a C `int`.
#[no_mangle]
pub extern "C" fn issetugid() -> c_int {
    if startup_security::is_secure() {
        1
    } else {
        0
    }
}
