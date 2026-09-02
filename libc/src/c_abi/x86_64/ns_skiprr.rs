//! Selected static Linux/x86-64 DNS resource-record span C ABI boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/ns_parse.c::ns_skiprr` to this one caller-owned wire-range
//! operation. It walks `count` question records or resource records from a
//! bounded packet span, preserving musl's `dn_skipname` name-span and
//! `ns_get16` network-byte-order dependencies. A malformed span returns `-1`
//! and publishes Linux `EMSGSIZE` in the selected initial-TLS `errno` slot.
//!
//! This target-local helper owns neither a DNS message handle nor resolver
//! configuration, `/etc/resolv.conf`, DNS packet I/O, socket, netdb, hosts,
//! allocation, or mutable parser state. `ns_initparse`, `ns_parserr`,
//! `ns_name_uncompress`, `dn_expand`, DNS name compression, resolver state,
//! and all resolver/network capability promotion remain separate work.

use core::ffi::c_int;

const NS_S_QD: c_int = 0;
const QUESTION_FIXED_BYTES: usize = 2 * 2;
const RESOURCE_FIXED_BYTES: usize = 4 + 2;
const EMSGSIZE: c_int = 90;

// Keep musl's two selected wire helpers as object-level C ABI dependencies.
// This leaves their separate source mappings and direct static evidence intact
// instead of copying their byte-range behavior into the RR-span loop.
unsafe extern "C" {
    #[link_name = "dn_skipname"]
    fn selected_dn_skipname(source: *const u8, end: *const u8) -> c_int;
    #[link_name = "ns_get16"]
    fn selected_ns_get16(bytes: *const u8) -> u32;
}

/// Advance across `count` caller-owned DNS question or resource-record spans.
///
/// # Safety
///
/// `ptr..eom` must delimit one ordered readable byte range in one allocation,
/// and `count` must be nonnegative. For a non-question section, each selected
/// record must have the wire layout musl accepts: name, type, class, TTL,
/// RDLENGTH, then RDATA. This entry neither follows DNS compression pointers
/// nor retains the range; it delegates name span rules to the selected
/// `dn_skipname` C ABI and reads RDLENGTH through the selected `ns_get16` C ABI.
// Keep this parser precursor as a direct archive dependency when the selected
// message-parser block advances a caller-chosen record index.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn ns_skiprr(
    ptr: *const u8,
    eom: *const u8,
    section: c_int,
    count: c_int,
) -> c_int {
    let total_bytes = (eom as usize).wrapping_sub(ptr as usize);
    let mut consumed = 0_usize;
    let mut remaining_records = count;

    while remaining_records != 0 {
        let cursor = unsafe { ptr.add(consumed) };
        let name_bytes = unsafe { selected_dn_skipname(cursor, eom) };
        if name_bytes < 0 {
            return unsafe { malformed() };
        }

        let name_bytes = name_bytes as usize;
        let remaining_bytes = total_bytes.wrapping_sub(consumed);
        if name_bytes.wrapping_add(QUESTION_FIXED_BYTES) > remaining_bytes {
            return unsafe { malformed() };
        }
        consumed = consumed.wrapping_add(name_bytes + QUESTION_FIXED_BYTES);

        if section != NS_S_QD {
            let remaining_bytes = total_bytes.wrapping_sub(consumed);
            if RESOURCE_FIXED_BYTES > remaining_bytes {
                return unsafe { malformed() };
            }

            // Skip TTL before using the separately selected wire read for
            // RDLENGTH, exactly as musl's NS_GET16 macro does.
            consumed = consumed.wrapping_add(4);
            let rdata_bytes = unsafe { selected_ns_get16(ptr.add(consumed)) } as usize;
            consumed = consumed.wrapping_add(2);
            if rdata_bytes > total_bytes.wrapping_sub(consumed) {
                return unsafe { malformed() };
            }
            consumed = consumed.wrapping_add(rdata_bytes);
        }

        // Musl spells the loop `while (count--)`. Valid callers supply a
        // nonnegative count; wrapping retains the same first-record behavior
        // for other C inputs without introducing Rust signed-overflow UB.
        remaining_records = remaining_records.wrapping_sub(1);
    }

    consumed as c_int
}

#[inline]
unsafe fn malformed() -> c_int {
    unsafe { super::errno::set_errno(EMSGSIZE) };
    -1
}
