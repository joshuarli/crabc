//! Isolated Linux/x86-64 nameserver 16-bit wire-write C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/ns_parse.c`'s `ns_put16` to this one public operation. It
//! writes the low 16 bits of C `unsigned` into exactly two caller-owned bytes
//! in network byte order. The separately defined `ns_get16`, `ns_get32`,
//! `ns_put32`, and nameserver parser operations in that source remain outside
//! this leaf.
//!
//! This target-local byte codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::c_uint;

/// Write one unaligned caller-owned 16-bit DNS wire value in network byte order.
///
/// # Safety
///
/// `bytes` must point to at least two writable bytes in one allocation. As in
/// musl's C ABI, this function does not validate, retain, align, or own the
/// output; it writes exactly those two bytes, truncates `value` to its low 16
/// bits, and does not read memory or consult nameserver state.
#[no_mangle]
pub unsafe extern "C" fn ns_put16(value: c_uint, bytes: *mut u8) {
    unsafe {
        core::ptr::write(bytes, (value >> 8) as u8);
        core::ptr::write(bytes.add(1), value as u8);
    }
}
