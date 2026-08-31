//! Isolated Linux/x86-64 C classful IPv4 arithmetic.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/inet_legacy.c` to four adjacent legacy functions:
//! `inet_network`, `inet_makeaddr`, `inet_lnaof`, and `inet_netof`. This
//! target-local leaf selects exactly the two self-contained arithmetic
//! functions [`inet_makeaddr`] and [`inet_lnaof`]. It deliberately leaves
//! `inet_network` (and its `inet_addr` call) and `inet_netof` unselected.
//!
//! `inet_makeaddr` ORs a raw caller-supplied host word with the network number
//! shifted by 24, 16, or 8 bits for `n < 256`, `n < 65536`, or otherwise.
//! `inet_lnaof` reads that raw `struct in_addr::s_addr` word, uses its high
//! byte to choose the `< 128`, `< 192`, or remaining class, then masks 24, 16,
//! or 8 low bits. These are legacy raw-word operations: this leaf does not
//! select byte-order conversion, `inet_ntoa` scratch storage, errno, h_errno,
//! TLS, allocation, syscalls, resolver configuration, DNS, `/etc/hosts`,
//! `/etc/resolv.conf`, netdb, interfaces, sockets, or public support.

use core::ffi::c_uint;

/// The x86 C ABI layout of the by-value `<arpa/inet.h>` IPv4 record.
///
/// System V AMD64 carries this one-word record in `edi` and returns it in
/// `eax`; keeping the record local prevents this private evidence leaf from
/// establishing a Rust-facing address API.
#[repr(C)]
pub struct InAddr {
    s_addr: c_uint,
}

/// Construct musl's legacy classful IPv4 raw address word.
///
/// This intentionally preserves musl's OR rather than masking `host`: callers
/// observe all caller-provided bits that overlap the selected classful prefix.
#[no_mangle]
pub extern "C" fn inet_makeaddr(network: c_uint, mut host: c_uint) -> InAddr {
    if network < 256 {
        host |= network << 24;
    } else if network < 65_536 {
        host |= network << 16;
    } else {
        host |= network << 8;
    }
    InAddr { s_addr: host }
}

/// Return musl's legacy classful local-address part from a raw IPv4 word.
#[no_mangle]
pub extern "C" fn inet_lnaof(address: InAddr) -> c_uint {
    let host = address.s_addr;

    if host >> 24 < 128 {
        host & 0x00ff_ffff
    } else if host >> 24 < 192 {
        host & 0x0000_ffff
    } else {
        host & 0x0000_00ff
    }
}
