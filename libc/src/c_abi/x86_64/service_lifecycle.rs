//! Selected static Linux/x86-64 legacy service-lifecycle C ABI boundary.
//!
//! This private provider owns exactly musl's `void setservent(int)` and
//! `struct servent *getservent(void)` spellings. Pinned musl 1.2.6
//! `src/network/serv.c` makes the former a no-op and the latter return null.
//! Together with the separately-owned no-op `endservent`, those are the full
//! source-closed lifecycle trio; they deliberately do not create a service
//! cursor or implement lookup/enumeration.
//!
//! The functions do not inspect their input, allocate, write errno or h_errno,
//! access TLS/global state, make syscalls, or touch `/etc/services`. They are
//! not service-database, resolver, NSS, socket, libc.so, CRT, loader, sysroot,
//! family-completion, promotion, or public-x86 support work.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/network/serv.c::{setservent,getservent}`.

use core::ffi::{c_int, c_void};

/// Preserve musl's stateless service-enumeration setup boundary.
#[no_mangle]
pub extern "C" fn setservent(_stayopen: c_int) {}

/// Return musl's source-closed absence of service enumeration state.
#[no_mangle]
pub extern "C" fn getservent() -> *mut c_void {
    core::ptr::null_mut()
}
