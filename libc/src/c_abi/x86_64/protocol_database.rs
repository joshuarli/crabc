//! Selected static Linux/x86-64 legacy protocol-database C ABI.
//!
//! This module translates the complete five-entry public block in pinned musl
//! 1.2.6 `src/network/proto.c`: `endprotoent`, `getprotobyname`,
//! `getprotobynumber`, `getprotoent`, and `setprotoent`.  Musl deliberately
//! does not read `/etc/protocols` here. It exposes one immutable, compact
//! protocol table and one process-global non-reentrant enumeration index plus
//! result record. The direct comparison helpers below replace only musl's
//! local `strlen`/`strcmp` dependencies, preserving that source's table,
//! reset, lookup-composition, result-identity, and NULL-alias behavior
//! without selecting the byte-string C ABI, allocation, files, DNS, or a
//! resolver runtime.
//!
//! The generic `network_databases_exports.rs` implementation owns a distinct
//! `/etc/protocols` snapshot ABI for the broader AArch64 C surface. It is not
//! a fallback for this static x86 compatibility block: differing aliases,
//! case rules, storage, and file/error behavior would obscure musl's exact
//! `proto.c` boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

use core::ffi::{c_char, c_int};

#[repr(C)]
pub(crate) struct CabiProtoent {
    p_name: *mut c_char,
    p_aliases: *mut *mut c_char,
    p_proto: c_int,
}

// Keep musl's byte-encoded source table verbatim: a protocol number precedes
// every NUL-terminated name, including the compiler-appended terminator of
// musl's final `"\377raw"` C string literal.
static PROTOCOLS: &[u8] = b"\0ip\0\
\x01icmp\0\
\x02igmp\0\
\x03ggp\0\
\x04ipencap\0\
\x05st\0\
\x06tcp\0\
\x08egp\0\
\x0cpup\0\
\x11udp\0\
\x14hmp\0\
\x16xns-idp\0\
\x1brdp\0\
\x1diso-tp4\0\
\x24xtp\0\
\x25ddp\0\
\x26idpr-cmtp\0\
\x29ipv6\0\
\x2bipv6-route\0\
\x2cipv6-frag\0\
\x2didrp\0\
\x2ersvp\0\
\x2fgre\0\
\x32esp\0\
\x33ah\0\
\x39skip\0\
\x3aipv6-icmp\0\
\x3bipv6-nonxt\0\
\x3cipv6-opts\0\
\x49rspf\0\
\x51vmtp\0\
\x59ospf\0\
\x5eipip\0\
\x62encap\0\
\x67pim\0\
\xffraw\0";

// This matches musl's `static int idx`, `static struct protoent p`, and
// `static const char *aliases` process-global storage. These functions are
// deliberately non-reentrant; C callers must externally serialize concurrent
// calls exactly as they do for musl's legacy netdb interface.
static mut PROTOCOL_INDEX: usize = 0;
static mut PROTOCOL_RESULT: CabiProtoent = CabiProtoent {
    p_name: core::ptr::null_mut(),
    p_aliases: core::ptr::null_mut(),
    p_proto: 0,
};
static mut PROTOCOL_ALIASES: *mut c_char = core::ptr::null_mut();

#[inline]
unsafe fn c_string_length(value: *const u8) -> usize {
    let mut length = 0usize;
    // Keep the fixed-table provider self-contained. LLVM otherwise recognizes
    // this canonical NUL scan and lowers it to an external `strlen` call,
    // which would select an unrelated public byte-string ABI entry. Volatile
    // reads preserve the source's bytewise result while preventing that
    // replacement at this intentionally dependency-free boundary.
    while unsafe { core::ptr::read_volatile(value.add(length)) } != 0 {
        length += 1;
    }
    length
}

#[inline]
unsafe fn c_strings_equal(left: *const c_char, right: *const c_char) -> bool {
    let mut index = 0usize;
    loop {
        let left_byte = unsafe { core::ptr::read_volatile((left as *const u8).add(index)) };
        let right_byte = unsafe { core::ptr::read_volatile((right as *const u8).add(index)) };
        if left_byte != right_byte {
            return false;
        }
        if left_byte == 0 {
            return true;
        }
        index += 1;
    }
}

/// Reset musl's shared protocol enumeration index.
///
/// # Safety
///
/// The legacy protocol database has one shared mutable cursor and result
/// record. Callers must externally serialize this call with every other
/// selected protocol-database entry point.
#[no_mangle]
pub unsafe extern "C" fn endprotoent() {
    unsafe { PROTOCOL_INDEX = 0 };
}

/// Reset musl's shared protocol enumeration index, ignoring `stayopen`.
///
/// # Safety
///
/// The legacy protocol database has one shared mutable cursor and result
/// record. Callers must externally serialize this call with every other
/// selected protocol-database entry point.
#[no_mangle]
pub unsafe extern "C" fn setprotoent(_stayopen: c_int) {
    unsafe { PROTOCOL_INDEX = 0 };
}

/// Return the next entry from musl's fixed shared protocol table.
///
/// # Safety
///
/// The returned `protoent` and its name/alias pointer slots are process-global
/// storage overwritten by the next selected protocol-database call. Callers
/// must externally serialize access and must not retain the result across a
/// later call to this non-reentrant legacy API.
#[no_mangle]
pub unsafe extern "C" fn getprotoent() -> *mut CabiProtoent {
    let index = unsafe { PROTOCOL_INDEX };
    if index >= PROTOCOLS.len() {
        return core::ptr::null_mut();
    }

    let entry = unsafe { PROTOCOLS.as_ptr().add(index) };
    let name = unsafe { entry.add(1) };
    let name_length = unsafe { c_string_length(name) };
    unsafe {
        PROTOCOL_RESULT.p_proto = entry.read() as c_int;
        PROTOCOL_RESULT.p_name = name.cast::<c_char>() as *mut c_char;
        PROTOCOL_RESULT.p_aliases = core::ptr::addr_of_mut!(PROTOCOL_ALIASES);
        PROTOCOL_INDEX = index + name_length + 2;
        core::ptr::addr_of_mut!(PROTOCOL_RESULT)
    }
}

/// Search musl's fixed protocol table by exact, case-sensitive name.
///
/// # Safety
///
/// `name` must designate a readable NUL-terminated C string. The returned
/// shared result has the same externally serialized, next-call-overwritten
/// lifetime as `getprotoent`.
#[no_mangle]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut CabiProtoent {
    unsafe { endprotoent() };
    loop {
        let entry = unsafe { getprotoent() };
        if entry.is_null() || unsafe { c_strings_equal(name, (*entry).p_name) } {
            return entry;
        }
    }
}

/// Search musl's fixed protocol table by its numeric protocol value.
///
/// # Safety
///
/// The returned shared result has the same externally serialized,
/// next-call-overwritten lifetime as `getprotoent`.
#[no_mangle]
pub unsafe extern "C" fn getprotobynumber(number: c_int) -> *mut CabiProtoent {
    unsafe { endprotoent() };
    loop {
        let entry = unsafe { getprotoent() };
        if entry.is_null() || unsafe { (*entry).p_proto == number } {
            return entry;
        }
    }
}
