//! Isolated Linux/x86-64 DNS wire-name expansion C ABI leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/dn_expand.c` to one hidden strong `__dn_expand` implementation
//! and its same-address weak public [`dn_expand`] alias. It follows a
//! caller-owned DNS compression pointer only inside the caller-supplied
//! `base..end` message range, writes one dotted name into caller-owned output,
//! and returns the initial encoded span length. The source caps usable output
//! space at 254 bytes and detects pointer cycles with a two-byte iteration
//! budget.
//!
//! This target-local codec has no resolver state, `/etc/resolv.conf`, DNS
//! packet I/O, socket, netdb, errno/TLS, allocation, syscall, mutable state,
//! address-codec, interface, or Ethernet dependency. It is private static C
//! ABI evidence, not DNS resolver completion or public x86 support.

use core::ffi::{c_char, c_int};

/// Decode one caller-owned compressed DNS name into caller-owned dotted text.
///
/// # Safety
///
/// `base..end` must delimit one readable DNS message allocation, and `source`
/// must lie in that range unless it equals `end`. `destination` must designate
/// at least `space` writable bytes in one allocation when `space > 0`; no
/// destination is accessed when `source == end` or `space <= 0`. As in musl,
/// the pointers are neither retained nor aligned, and caller-owned input and
/// output may overlap because bytes are copied forward one at a time.
#[no_mangle]
pub unsafe extern "C" fn __dn_expand(
    base: *const u8,
    end: *const u8,
    source: *const u8,
    destination: *mut c_char,
    space: c_int,
) -> c_int {
    if source == end || space <= 0 {
        return -1;
    }

    let message_bytes = (end as usize).wrapping_sub(base as usize);
    let mut cursor = source;
    let origin = destination.cast::<u8>();
    let mut output = origin;
    let output_end = unsafe {
        origin.add(if space > 254 {
            254
        } else {
            space as usize
        })
    };
    let mut consumed: c_int = -1;
    let mut iteration = 0usize;

    while iteration < message_bytes {
        let label = unsafe { core::ptr::read(cursor) };
        if label & 0xc0 != 0 {
            if unsafe { cursor.add(1) } == end {
                return -1;
            }
            let offset = (((label & 0x3f) as usize) << 8)
                | unsafe { core::ptr::read(cursor.add(1)) } as usize;
            if consumed < 0 {
                consumed = (unsafe { cursor.add(2) } as usize)
                    .wrapping_sub(source as usize) as c_int;
            }
            if offset >= message_bytes {
                return -1;
            }
            cursor = unsafe { base.add(offset) };
        } else if label != 0 {
            if output != origin {
                unsafe { core::ptr::write(output, b'.') };
                output = unsafe { output.add(1) };
            }
            let length = label as usize;
            cursor = unsafe { cursor.add(1) };
            if length >= (end as usize).wrapping_sub(cursor as usize)
                || length >= (output_end as usize).wrapping_sub(output as usize)
            {
                return -1;
            }
            let mut remaining = length;
            while remaining != 0 {
                let byte = unsafe { core::ptr::read(cursor) };
                unsafe { core::ptr::write(output, byte) };
                cursor = unsafe { cursor.add(1) };
                output = unsafe { output.add(1) };
                remaining -= 1;
            }
        } else {
            unsafe { core::ptr::write(output, 0) };
            if consumed < 0 {
                consumed = (unsafe { cursor.add(1) } as usize)
                    .wrapping_sub(source as usize) as c_int;
            }
            return consumed;
        }
        iteration += 2;
    }

    -1
}

// Musl's `weak_alias(__dn_expand, dn_expand)` requires the public and hidden
// names to identify one code address. A Rust forwarding wrapper would change
// both that address identity and the static link-time weak-override contract.
core::arch::global_asm!(
    ".hidden __dn_expand",
    ".weak dn_expand",
    ".set dn_expand, __dn_expand",
);
