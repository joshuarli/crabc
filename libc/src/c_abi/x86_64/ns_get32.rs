//! Isolated Linux/x86-64 nameserver 32-bit wire-read C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/ns_parse.c`'s `ns_get32` to this one public operation. It
//! reads exactly four caller-owned bytes in network byte order and returns the
//! resulting 32-bit value widened to C `unsigned long`. The separately defined
//! `ns_get16`, `ns_put16`, `ns_put32`, and nameserver parser operations in that
//! source remain outside this leaf.
//!
//! This target-local byte codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::c_ulong;

/// Read one unaligned caller-owned 32-bit DNS wire value in network byte order.
///
/// # Safety
///
/// `bytes` must point to at least four readable bytes in one allocation. As in
/// musl's C ABI, this function does not validate, retain, align, or own the
/// input; it reads exactly those four bytes and does not write memory or
/// consult nameserver state. The returned LP64 C `unsigned long` has only the
/// decoded low 32 bits set.
#[no_mangle]
pub unsafe extern "C" fn ns_get32(bytes: *const u8) -> c_ulong {
    let first = unsafe { core::ptr::read(bytes) } as c_ulong;
    let second = unsafe { core::ptr::read(bytes.add(1)) } as c_ulong;
    let third = unsafe { core::ptr::read(bytes.add(2)) } as c_ulong;
    let fourth = unsafe { core::ptr::read(bytes.add(3)) } as c_ulong;
    (first << 24) | (second << 16) | (third << 8) | fourth
}
