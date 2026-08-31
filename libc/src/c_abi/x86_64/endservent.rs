//! Selected static Linux/x86-64 legacy service-database terminator C ABI boundary.
//!
//! This private leaf owns only musl's `void endservent(void)` spelling.
//! Pinned musl 1.2.6 `src/network/serv.c::endservent` has an empty body. Its
//! adjacent `setservent` and null-returning `getservent` spellings stay
//! unselected: this leaf neither opens nor closes `/etc/services`, owns no
//! service cursor, and makes no service-database, resolver, NSS, filesystem,
//! process, or network-policy claim. It is deliberately distinct from the
//! separate host/network terminator pair and does not alter the AArch64
//! dynamic network-database implementation.
//!
//! The System V AMD64 ABI gives this no-argument `void` entry no incoming C
//! argument words or return value. It has no mutable state, errno, TLS,
//! allocation, syscall, libc.so, CRT, loader, sysroot, family-completion,
//! promotion, or public x86 support boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

/// End musl's stateless legacy service-database enumeration boundary.
#[no_mangle]
pub extern "C" fn endservent() {}
