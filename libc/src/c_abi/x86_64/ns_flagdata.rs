//! Isolated Linux/x86-64 nameserver flag-accessor C ABI data leaf.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` places the public immutable
//! 128-byte [`_ns_flagdata`] object in the dependency-free
//! `.rodata._ns_flagdata` section of `src/network/ns_parse.c`. That source
//! object also contains parser code, but the data section has no relocations
//! and is selected here without the adjacent `ns_initparse`, `ns_parserr`,
//! `ns_skiprr`, `ns_name_uncompress`, or nameserver byte helpers. The sixteen
//! `(mask, shift)` pairs are the sole data dependency of the public
//! `<arpa/nameser.h>` `ns_msg_getflag` macro.
//!
//! This target-local read-only object has no code, mutable state, resolver
//! state, `/etc/resolv.conf`, DNS packet I/O, socket, netdb, errno/TLS,
//! allocation, syscall, interface, or Ethernet dependency. It is private
//! static C ABI evidence, not parser or resolver completion or public x86
//! support.

use core::ffi::c_int;

/// C layout of one `<arpa/nameser.h>` flag mask/shift record.
#[repr(C)]
pub struct NsFlagData {
    mask: c_int,
    shift: c_int,
}

/// Musl's immutable nameserver flag-accessor table.
#[no_mangle]
pub static _ns_flagdata: [NsFlagData; 16] = [
    NsFlagData { mask: 0x8000, shift: 15 },
    NsFlagData { mask: 0x7800, shift: 11 },
    NsFlagData { mask: 0x0400, shift: 10 },
    NsFlagData { mask: 0x0200, shift: 9 },
    NsFlagData { mask: 0x0100, shift: 8 },
    NsFlagData { mask: 0x0080, shift: 7 },
    NsFlagData { mask: 0x0040, shift: 6 },
    NsFlagData { mask: 0x0020, shift: 5 },
    NsFlagData { mask: 0x0010, shift: 4 },
    NsFlagData { mask: 0x000f, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
    NsFlagData { mask: 0, shift: 0 },
];
