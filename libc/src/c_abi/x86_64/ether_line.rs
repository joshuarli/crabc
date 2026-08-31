//! Selected static Linux/x86-64 legacy Ethernet-line C ABI boundary.
//!
//! This private leaf maps exactly to pinned musl 1.2.6
//! `src/network/ether.c::ether_line`. Its complete source body is
//! `return -1;`: it neither reads nor writes the input line, `ether_addr`, or
//! hostname pointer. The nearby `ether_aton[_r]`, `ether_ntoa[_r]`,
//! `ether_ntohost`, and `ether_hostton` entries remain unselected. In
//! particular, this is not `/etc/ethers` parsing or Ethernet address
//! conversion, mapping, resolver, socket, interface, or network policy.
//!
//! The System V AMD64 ABI passes the three pointer values in rdi/rsi/rdx and
//! returns the signed `int` result in eax. Since the selected musl body does
//! not dereference any pointer, null values are accepted by this isolated
//! source-shaped compatibility-failure boundary. It has no errno, TLS,
//! allocation, syscall, runtime, or mutable state.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

use core::ffi::{c_char, c_int};

/// C-layout spelling of the caller-owned six-octet Ethernet address.
#[repr(C)]
pub(super) struct CabiEtherAddr {
    _octets: [u8; 6],
}

/// Return musl's fixed unsupported legacy Ethernet-line result.
#[no_mangle]
pub extern "C" fn ether_line(
    _line: *const c_char,
    _address: *mut CabiEtherAddr,
    _hostname: *mut c_char,
) -> c_int {
    -1
}
