//! Isolated Linux/x86-64 nameserver 16-bit wire-read C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/ns_parse.c`'s `ns_get16` to this one public operation. It
//! reads exactly two caller-owned bytes in network byte order and returns the
//! resulting 16-bit value widened to C `unsigned`. The separately defined
//! `ns_get32`, `ns_put16`, `ns_put32`, and nameserver parser operations in
//! that source remain outside this leaf.
//!
//! This target-local byte codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::c_uint;

/// Read one unaligned caller-owned 16-bit DNS wire value in network byte order.
///
/// # Safety
///
/// `bytes` must point to at least two readable bytes in one allocation. As in
/// musl's C ABI, this function does not validate, retain, align, or own the
/// input; it reads exactly those two bytes and does not write memory or consult
/// nameserver state.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn ns_get16(bytes: *const u8) -> c_uint {
    let high = unsafe { core::ptr::read(bytes) } as c_uint;
    let low = unsafe { core::ptr::read(bytes.add(1)) } as c_uint;
    (high << 8) | low
}
