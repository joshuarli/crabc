//! Isolated Linux/x86-64 nameserver 32-bit wire-write C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/ns_parse.c`'s `ns_put32` to this one public operation. It
//! writes exactly four caller-owned bytes in network byte order from the low
//! 32 bits of C `unsigned long`. The separately defined `ns_get16`,
//! `ns_get32`, `ns_put16`, and nameserver parser operations in that source
//! remain outside this leaf.
//!
//! This target-local byte codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::c_ulong;

/// Write one unaligned caller-owned 32-bit DNS wire value in network byte order.
///
/// # Safety
///
/// `bytes` must point to at least four writable bytes in one allocation. As in
/// musl's C ABI, this function does not validate, retain, align, or own the
/// output; it writes exactly those four bytes and does not read memory or
/// consult nameserver state. It truncates `value` to its low 32 bits before
/// writing the most significant byte first.
#[no_mangle]
pub unsafe extern "C" fn ns_put32(value: c_ulong, bytes: *mut u8) {
    unsafe { core::ptr::write(bytes, (value >> 24) as u8) };
    unsafe { core::ptr::write(bytes.add(1), (value >> 16) as u8) };
    unsafe { core::ptr::write(bytes.add(2), (value >> 8) as u8) };
    unsafe { core::ptr::write(bytes.add(3), value as u8) };
}
