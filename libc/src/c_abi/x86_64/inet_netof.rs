//! Isolated Linux/x86-64 C classful IPv4 network-part extraction.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/inet_legacy.c` to four adjacent legacy functions:
//! `inet_network`, `inet_makeaddr`, `inet_lnaof`, and `inet_netof`. This
//! target-local leaf selects exactly the self-contained raw-word
//! [`inet_netof`] function. It deliberately leaves `inet_network` (and its `inet_addr` call),
//! plus the separately evidenced `inet_makeaddr` and `inet_lnaof` arithmetic
//! leaf, unselected by this artifact.
//!
//! `inet_netof` reads the raw `struct in_addr::s_addr` word, uses its high
//! byte to choose the `< 128`, `< 192`, or remaining class, then shifts 24,
//! 16, or 8 bits. This is a legacy raw-word operation: this leaf does not
//! select byte-order conversion, `inet_ntoa` scratch storage, errno, h_errno,
//! TLS, allocation, syscalls, resolver configuration, DNS, `/etc/hosts`,
//! `/etc/resolv.conf`, netdb, interfaces, sockets, or public support.

use core::ffi::c_uint;

/// The x86 C ABI layout of the by-value `<arpa/inet.h>` IPv4 record.
///
/// System V AMD64 carries this one-word record in `edi` and returns the
/// `in_addr_t` result in `eax`; keeping the record local prevents this private
/// evidence leaf from establishing a Rust-facing address API.
#[repr(C)]
pub struct InAddr {
    s_addr: c_uint,
}

/// Return musl's legacy classful network part from a raw IPv4 word.
#[no_mangle]
pub extern "C" fn inet_netof(address: InAddr) -> c_uint {
    let host = address.s_addr;

    if host >> 24 < 128 {
        host >> 24
    } else if host >> 24 < 192 {
        host >> 16
    } else {
        host >> 8
    }
}
