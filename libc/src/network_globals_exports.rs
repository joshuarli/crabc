// resolver compatibility globals and IPv6 constants.
//
// The resolver implementation grows independently, but these names have
// stable, observable contracts today: IPv6 callers may pass the exported
// all-zero and loopback objects to socket APIs, while legacy resolver callers
// use `h_errno` and its accessor to retain an error across helper calls.

#[repr(C)]
pub struct CabiIn6Addr {
    pub s6_addr: [u8; 16],
}

#[no_mangle]
pub static in6addr_any: CabiIn6Addr = CabiIn6Addr { s6_addr: [0; 16] };
#[no_mangle]
pub static in6addr_loopback: CabiIn6Addr = CabiIn6Addr {
    s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
};

#[no_mangle]
pub static mut h_errno: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn __h_errno_location() -> *mut c_int {
    &raw mut h_errno
}


static CABI_HERR_UNKNOWN: &[u8] = b"Unknown error\0";
static CABI_HERR_HOST_NOT_FOUND: &[u8] = b"Host not found\0";
static CABI_HERR_TRY_AGAIN: &[u8] = b"Try again\0";
static CABI_HERR_NO_RECOVERY: &[u8] = b"Non-recoverable error\0";
static CABI_HERR_NO_DATA: &[u8] = b"Address not available\0";

#[inline]
unsafe fn cabi_herror_message(error: c_int) -> *const c_char {
    match error {
        1 => CABI_HERR_HOST_NOT_FOUND.as_ptr() as *const c_char,
        2 => CABI_HERR_TRY_AGAIN.as_ptr() as *const c_char,
        3 => CABI_HERR_NO_RECOVERY.as_ptr() as *const c_char,
        4 => CABI_HERR_NO_DATA.as_ptr() as *const c_char,
        _ => CABI_HERR_UNKNOWN.as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hstrerror(error: c_int) -> *const c_char {
    cabi_herror_message(error)
}

#[no_mangle]
pub unsafe extern "C" fn herror(prefix: *const c_char) {
    if stderr.is_null() {
        return;
    }
    if !prefix.is_null() && *prefix != 0 {
        let _ = fputs(prefix, stderr);
        let _ = fputs(b": \0".as_ptr() as *const c_char, stderr);
    }
    let _ = fputs(cabi_herror_message(h_errno), stderr);
    let _ = fputc(b'\n' as c_int, stderr);
}

// These messages are part of the `netdb.h` API even when a caller uses only
// a numeric address and therefore never enters the DNS resolver.
#[no_mangle]
pub unsafe extern "C" fn gai_strerror(error: c_int) -> *const c_char {
    match error {
        -1 => b"Invalid flags\0".as_ptr() as *const c_char,
        -2 => b"Name does not resolve\0".as_ptr() as *const c_char,
        -3 => CABI_HERR_TRY_AGAIN.as_ptr() as *const c_char,
        -4 => CABI_HERR_NO_RECOVERY.as_ptr() as *const c_char,
        -6 => b"Unrecognized address family or invalid length\0".as_ptr() as *const c_char,
        -7 => b"Unrecognized socket type\0".as_ptr() as *const c_char,
        -8 => b"Unrecognized service\0".as_ptr() as *const c_char,
        -10 => b"Out of memory\0".as_ptr() as *const c_char,
        -11 => b"System error\0".as_ptr() as *const c_char,
        -12 => b"Overflow\0".as_ptr() as *const c_char,
        _ => CABI_HERR_UNKNOWN.as_ptr() as *const c_char,
    }
}

// musl's resolver packet parser is intentionally small: it only decodes the
// wire-format fields and walks record boundaries.  Keep the packet bounds
// checks at this boundary so malformed responses cannot make callers read
// outside the received datagram.

const CABI_EMSGSIZE: c_int = 90;
const CABI_ENODEV: c_int = 19;
const CABI_NS_SECT_MAX: c_int = 4;

#[repr(C)]
pub struct CabiNsMsg {
    pub _msg: *const u8,
    pub _eom: *const u8,
    pub _id: u16,
    pub _flags: u16,
    pub _counts: [u16; 4],
    pub _sections: [*const u8; 4],
    pub _sect: c_int,
    pub _rrnum: c_int,
    pub _msg_ptr: *const u8,
}

#[repr(C)]
pub struct CabiNsRR {
    pub name: [c_char; 1025],
    pub type_: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: *const u8,
}

#[repr(C)]
pub struct CabiNsFlagData {
    pub mask: c_int,
    pub shift: c_int,
}

// This is part of the public nameser.h accessor-macro ABI.  Its layout is
// two 32-bit integers and therefore remains 128 bytes on the supported
// 64-bit targets, matching musl's ns_parse.o object.
#[no_mangle]
pub static _ns_flagdata: [CabiNsFlagData; 16] = [
    CabiNsFlagData { mask: 0x8000, shift: 15 },
    CabiNsFlagData { mask: 0x7800, shift: 11 },
    CabiNsFlagData { mask: 0x0400, shift: 10 },
    CabiNsFlagData { mask: 0x0200, shift: 9 },
    CabiNsFlagData { mask: 0x0100, shift: 8 },
    CabiNsFlagData { mask: 0x0080, shift: 7 },
    CabiNsFlagData { mask: 0x0040, shift: 6 },
    CabiNsFlagData { mask: 0x0020, shift: 5 },
    CabiNsFlagData { mask: 0x0010, shift: 4 },
    CabiNsFlagData { mask: 0x000f, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
    CabiNsFlagData { mask: 0, shift: 0 },
];

#[inline]
unsafe fn cabi_ns_set_errno(value: c_int) {
    ERRNO = value;
}

// `network_interface_exports.rs` is also selected by the isolated x86 static
// interface artifact. Keep its errno reads and writes behind this textual
// include seam so that artifact reaches only its target-local errno owner.
#[inline]
fn cabi_interface_set_errno(value: c_int) {
    unsafe { ERRNO = value };
}

#[inline]
fn cabi_interface_errno() -> c_int {
    unsafe { ERRNO }
}

#[inline]
unsafe fn cabi_ns_range(base: *const u8, end: *const u8) -> Option<(usize, usize)> {
    if base.is_null() || end.is_null() {
        return None;
    }
    let b = base as usize;
    let e = end as usize;
    if e < b {
        None
    } else {
        Some((b, e))
    }
}

// musl's dn_skipname consumes the encoded name itself, but does not follow a
// compression pointer.  Following is deliberately left to dn_expand, which
// has the complete message bounds and loop budget needed to decode a name.
#[no_mangle]
pub unsafe extern "C" fn dn_skipname(src: *const u8, end: *const u8) -> c_int {
    let (start, eom) = match cabi_ns_range(src, end) {
        Some(range) => range,
        None => return -1,
    };
    let mut p = start;
    while p < eom {
        let label = *(p as *const u8);
        if label == 0 {
            let consumed = p - start + 1;
            return if consumed <= c_int::MAX as usize {
                consumed as c_int
            } else {
                -1
            };
        }
        if label & 0xc0 != 0 {
            if eom - p < 2 {
                return -1;
            }
            let consumed = p - start + 2;
            return if consumed <= c_int::MAX as usize {
                consumed as c_int
            } else {
                -1
            };
        }
        let advance = label as usize + 1;
        if advance > eom - p {
            return -1;
        }
        p += advance;
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn ns_get16(cp: *const u8) -> c_uint {
    ((*(cp) as c_uint) << 8) | *(cp.add(1)) as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ns_get32(cp: *const u8) -> c_ulong {
    ((*(cp) as c_ulong) << 24)
        | ((*(cp.add(1)) as c_ulong) << 16)
        | ((*(cp.add(2)) as c_ulong) << 8)
        | (*(cp.add(3)) as c_ulong)
}

#[no_mangle]
pub unsafe extern "C" fn ns_put16(value: c_uint, cp: *mut u8) {
    *cp = (value >> 8) as u8;
    *cp.add(1) = value as u8;
}

#[no_mangle]
pub unsafe extern "C" fn ns_put32(value: c_ulong, cp: *mut u8) {
    *cp = (value >> 24) as u8;
    *cp.add(1) = (value >> 16) as u8;
    *cp.add(2) = (value >> 8) as u8;
    *cp.add(3) = value as u8;
}

#[no_mangle]
pub unsafe extern "C" fn ns_skiprr(
    ptr: *const u8,
    eom: *const u8,
    section: c_int,
    mut count: c_int,
) -> c_int {
    let (start, end) = match cabi_ns_range(ptr, eom) {
        Some(range) => range,
        None => {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
    };
    if section < 0 || section >= CABI_NS_SECT_MAX || count < 0 {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }

    let mut p = start;
    while count > 0 {
        let name_len = dn_skipname(p as *const u8, end as *const u8);
        if name_len < 0 {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
        let name_len = name_len as usize;
        if name_len > end - p || end - p - name_len < 4 {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
        p += name_len + 4;
        if section != 0 {
            if end - p < 6 {
                cabi_ns_set_errno(CABI_EMSGSIZE);
                return -1;
            }
            p += 4;
            let rdlength = ns_get16(p as *const u8) as usize;
            p += 2;
            if rdlength > end - p {
                cabi_ns_set_errno(CABI_EMSGSIZE);
                return -1;
            }
            p += rdlength;
        }
        count -= 1;
    }

    let consumed = p - start;
    if consumed > c_int::MAX as usize {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }
    consumed as c_int
}

#[no_mangle]
pub unsafe extern "C" fn ns_initparse(
    msg: *const u8,
    msglen: c_int,
    handle: *mut CabiNsMsg,
) -> c_int {
    if handle.is_null() || msg.is_null() || msglen < 12 {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }
    let msg_end = (msg as usize).checked_add(msglen as usize);
    let msg_end = match msg_end {
        Some(end) => end,
        None => {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
    };
    let handle = &mut *handle;
    handle._msg = msg;
    handle._eom = msg_end as *const u8;

    let mut p = msg;
    handle._id = ns_get16(p) as u16;
    p = p.add(2);
    handle._flags = ns_get16(p) as u16;
    p = p.add(2);
    let mut i = 0;
    while i < 4 {
        handle._counts[i] = ns_get16(p) as u16;
        p = p.add(2);
        i += 1;
    }

    i = 0;
    while i < 4 {
        if handle._counts[i] != 0 {
            handle._sections[i] = p;
            let consumed = ns_skiprr(p, handle._eom, i as c_int, handle._counts[i] as c_int);
            if consumed < 0 {
                return -1;
            }
            p = p.add(consumed as usize);
        } else {
            handle._sections[i] = core::ptr::null();
        }
        i += 1;
    }

    if p as usize != msg_end {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }
    handle._sect = CABI_NS_SECT_MAX;
    handle._rrnum = -1;
    handle._msg_ptr = core::ptr::null();
    0
}

#[no_mangle]
pub unsafe extern "C" fn ns_parserr(
    handle: *mut CabiNsMsg,
    section: c_int,
    mut rrnum: c_int,
    rr: *mut CabiNsRR,
) -> c_int {
    if handle.is_null() || rr.is_null() || section < 0 || section >= CABI_NS_SECT_MAX {
        cabi_ns_set_errno(CABI_ENODEV);
        return -1;
    }
    let handle = &mut *handle;
    if section != handle._sect {
        handle._sect = section;
        handle._rrnum = 0;
        handle._msg_ptr = handle._sections[section as usize];
    }
    if rrnum == -1 {
        rrnum = handle._rrnum;
    }
    if rrnum < 0 || rrnum >= handle._counts[section as usize] as c_int {
        cabi_ns_set_errno(CABI_ENODEV);
        return -1;
    }
    if rrnum < handle._rrnum {
        handle._rrnum = 0;
        handle._msg_ptr = handle._sections[section as usize];
    }
    if rrnum > handle._rrnum {
        let skipped = ns_skiprr(
            handle._msg_ptr,
            handle._eom,
            section,
            rrnum - handle._rrnum,
        );
        if skipped < 0 {
            return -1;
        }
        handle._msg_ptr = handle._msg_ptr.add(skipped as usize);
        handle._rrnum = rrnum;
    }

    let parsed = ns_name_uncompress(
        handle._msg,
        handle._eom,
        handle._msg_ptr,
        (*rr).name.as_mut_ptr(),
        1025,
    );
    if parsed < 0 {
        return -1;
    }
    handle._msg_ptr = handle._msg_ptr.add(parsed as usize);
    let remaining = (handle._eom as usize).wrapping_sub(handle._msg_ptr as usize);
    if remaining < 4 {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }
    (*rr).type_ = ns_get16(handle._msg_ptr) as u16;
    handle._msg_ptr = handle._msg_ptr.add(2);
    (*rr).rr_class = ns_get16(handle._msg_ptr) as u16;
    handle._msg_ptr = handle._msg_ptr.add(2);
    if section != 0 {
        if (handle._eom as usize).wrapping_sub(handle._msg_ptr as usize) < 6 {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
        (*rr).ttl = ns_get32(handle._msg_ptr) as u32;
        handle._msg_ptr = handle._msg_ptr.add(4);
        (*rr).rdlength = ns_get16(handle._msg_ptr) as u16;
        handle._msg_ptr = handle._msg_ptr.add(2);
        if (*rr).rdlength as usize > (handle._eom as usize).wrapping_sub(handle._msg_ptr as usize) {
            cabi_ns_set_errno(CABI_EMSGSIZE);
            return -1;
        }
        (*rr).rdata = handle._msg_ptr;
        handle._msg_ptr = handle._msg_ptr.add((*rr).rdlength as usize);
    } else {
        (*rr).ttl = 0;
        (*rr).rdlength = 0;
        (*rr).rdata = core::ptr::null();
    }

    handle._rrnum += 1;
    if handle._rrnum > handle._counts[section as usize] as c_int {
        handle._sect = section + 1;
        if handle._sect == CABI_NS_SECT_MAX {
            handle._rrnum = -1;
            handle._msg_ptr = core::ptr::null();
        } else {
            handle._rrnum = 0;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn ns_name_uncompress(
    msg: *const u8,
    eom: *const u8,
    src: *const u8,
    dst: *mut c_char,
    dstsiz: usize,
) -> c_int {
    if msg.is_null()
        || eom.is_null()
        || src.is_null()
        || dst.is_null()
        || dstsiz == 0
        || dstsiz > c_int::MAX as usize
    {
        cabi_ns_set_errno(CABI_EMSGSIZE);
        return -1;
    }
    let result = dn_expand(msg, eom, src, dst, dstsiz as c_int);
    if result < 0 {
        cabi_ns_set_errno(CABI_EMSGSIZE);
    }
    result
}
