//! Isolated Linux/x86-64 DNS wire-name span C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/dn_skipname.c` to exactly one dependency-free public function:
//! [`dn_skipname`]. It advances through a caller-owned byte range until a root
//! label, consumes exactly two bytes for an octet at least 192, or returns -1
//! when the range ends first. In particular, musl deliberately treats every
//! octet below 192 as a label length, including 64 through 191.
//!
//! This target-local codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::c_int;

/// Advance across one caller-owned encoded DNS name without following pointers.
///
/// # Safety
///
/// `source..end` must delimit one readable byte range in one allocation. As in
/// musl's C ABI, the function may read the first byte of each encoded label and
/// has no ownership, alignment, resolver-state, or packet-I/O contract.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn dn_skipname(source: *const u8, end: *const u8) -> c_int {
    let start = source as usize;
    let limit = end as usize;
    let mut cursor = start;

    while cursor < limit {
        let label = unsafe { core::ptr::read(cursor as *const u8) };
        if label == 0 {
            return cursor.wrapping_sub(start).wrapping_add(1) as c_int;
        }
        if label >= 192 {
            return if cursor.wrapping_add(1) < limit {
                cursor.wrapping_sub(start).wrapping_add(2) as c_int
            } else {
                -1
            };
        }

        let advance = label as usize + 1;
        if limit.wrapping_sub(cursor) < advance {
            return -1;
        }
        cursor = cursor.wrapping_add(advance);
    }

    -1
}
