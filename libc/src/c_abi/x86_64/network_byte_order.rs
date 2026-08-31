//! Selected static Linux/x86-64 network byte-order C ABI.
//!
//! This leaf owns exactly `htonl`, `htons`, `ntohl`, and `ntohs`. On the
//! selected little-endian x86-64 target each is a scalar byte reversal: the
//! two host-to-network and two network-to-host entry points intentionally
//! remain distinct exported C symbols even though their concrete operation is
//! the same. It has no pointer, errno, TLS, syscall, allocation, locale,
//! resolver, configuration-file, DNS, netdb, socket-transport, interface, or
//! mutable-state boundary. It is not general networking, a protocol parser,
//! an address codec, `inet_ntoa`, a C runtime, libc.so, a CRT, a loader, a
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/network/htonl.c` maps to `htonl` below.
//! - `src/network/htons.c` maps to `htons` below.
//! - `src/network/ntohl.c` maps to `ntohl` below.
//! - `src/network/ntohs.c` maps to `ntohs` below.
//!
//! Musl selects its byte reversal through a runtime endian-union branch so
//! the same source can serve both byte orders. This target root admits only
//! Linux/x86-64 little-endian, where that branch is always the `bswap_16` or
//! `bswap_32` route. `swap_bytes` is the direct scalar equivalent without
//! introducing a portability abstraction or an ambient endian probe.

/// Convert a 32-bit host-order value to network byte order.
#[no_mangle]
pub extern "C" fn htonl(value: u32) -> u32 {
    value.swap_bytes()
}

/// Convert a 16-bit host-order value to network byte order.
#[no_mangle]
pub extern "C" fn htons(value: u16) -> u16 {
    value.swap_bytes()
}

/// Convert a 32-bit network-order value to host byte order.
#[no_mangle]
pub extern "C" fn ntohl(value: u32) -> u32 {
    value.swap_bytes()
}

/// Convert a 16-bit network-order value to host byte order.
#[no_mangle]
pub extern "C" fn ntohs(value: u16) -> u16 {
    value.swap_bytes()
}
