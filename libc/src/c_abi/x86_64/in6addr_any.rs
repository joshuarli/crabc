//! Isolated Linux/x86-64 immutable IPv6 unspecified-address C ABI object.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/in6addr_any.c` to exactly one public read-only object:
//! `in6addr_any`. Its C `struct in6_addr` payload is sixteen zero bytes. The
//! sibling `src/network/in6addr_loopback.c` owns the distinct final-octet-one
//! `in6addr_loopback` object and is deliberately not composed here.
//!
//! This target-local data leaf has no code, mutable state, errno/TLS,
//! allocation, syscall, address conversion, IPv6 socket transport, resolver
//! configuration, DNS, `/etc/hosts`, `/etc/resolv.conf`, netdb, interface, or
//! Ethernet dependency. It is private static C ABI evidence, not resolver or
//! network-runtime completion and not public x86 support.

/// C-compatible public `struct in6_addr` storage for this one immutable object.
#[repr(C)]
pub struct In6Addr {
    in6_union: In6AddrUnion,
}

/// Musl's public in6_addr union keeps the IPv6 address object four-byte aligned.
#[repr(C)]
pub union In6AddrUnion {
    s6_addr: [u8; 16],
    s6_addr16: [u16; 8],
    s6_addr32: [u32; 4],
}

/// Musl's immutable IPv6 unspecified address.
#[no_mangle]
pub static in6addr_any: In6Addr = In6Addr {
    in6_union: In6AddrUnion { s6_addr: [0; 16] },
};
