//! Selected static Linux/x86-64 numeric `netdb.h` C ABI.
//!
//! This leaf deliberately stops at the deterministic boundary shared by the
//! address codecs and the public `netdb.h` records: numeric `getaddrinfo`,
//! `freeaddrinfo`, numeric-fallback `getnameinfo`, and `gai_strerror`.
//! It performs no `/etc/hosts` or `/etc/resolv.conf` access and sends no DNS
//! packet.  A nonnumeric node therefore returns `EAI_NONAME`; a symbolic
//! service returns `EAI_SERVICE`. `AI_ADDRCONFIG` is accepted but has no
//! additional effect for already-numeric nodes, so this leaf still performs
//! no interface inspection. Those limits are intentional, visible, and kept
//! out of the selected comparison cases rather than hidden behind a fallback.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/network/getaddrinfo.c` supplies the public record, numeric-node,
//!   numeric-service, passive-node, mapped-v4, and result-list contracts.
//! - `src/network/freeaddrinfo.c` supplies the list-release contract.
//! - `src/network/getnameinfo.c` supplies the numeric host/service, flag, and
//!   output-capacity contracts.
//! - `src/network/gai_strerror.c` supplies the selected stable error strings.
//!
//! The private allocation is one anonymous page per result node.  It is not a
//! general allocator: the mapping is opaque to callers and can be released
//! only by this leaf's `freeaddrinfo` traversal.  This preserves the C-owned
//! result lifetime without admitting malloc, a resolver cache, or global
//! resolver state to the static x86 archive.

use core::ffi::{c_char, c_int, c_uint, c_void};

use super::{inet_address, raw_syscall};

const AF_UNSPEC: c_int = 0;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_TCP: c_int = 6;
const IPPROTO_UDP: c_int = 17;

const AI_PASSIVE: c_int = 0x0001;
const AI_CANONNAME: c_int = 0x0002;
const AI_NUMERICHOST: c_int = 0x0004;
const AI_V4MAPPED: c_int = 0x0008;
const AI_ALL: c_int = 0x0010;
const AI_ADDRCONFIG: c_int = 0x0020;
const AI_NUMERICSERV: c_int = 0x0400;
const AI_SUPPORTED: c_int = AI_PASSIVE
    | AI_CANONNAME
    | AI_NUMERICHOST
    | AI_V4MAPPED
    | AI_ALL
    | AI_ADDRCONFIG
    | AI_NUMERICSERV;

const NI_NUMERICHOST: c_int = 0x01;
const NI_NUMERICSERV: c_int = 0x02;
const NI_NOFQDN: c_int = 0x04;
const NI_NAMEREQD: c_int = 0x08;
const NI_DGRAM: c_int = 0x10;
const NI_NUMERICSCOPE: c_int = 0x100;
const NI_SUPPORTED: c_int = NI_NUMERICHOST
    | NI_NUMERICSERV
    | NI_NOFQDN
    | NI_NAMEREQD
    | NI_DGRAM
    | NI_NUMERICSCOPE;

const EAI_BADFLAGS: c_int = -1;
const EAI_NONAME: c_int = -2;
const EAI_FAMILY: c_int = -6;
const EAI_SOCKTYPE: c_int = -7;
const EAI_SERVICE: c_int = -8;
const EAI_MEMORY: c_int = -10;
const EAI_SYSTEM: c_int = -11;
const EAI_OVERFLOW: c_int = -12;

const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const PROT_READ_WRITE: i64 = 0x3;
const PAGE_SIZE: usize = 4096;
const LINUX_ERRNO_MAX: i64 = 4095;
const NODE_MAGIC: u64 = 0x4352_4142_434E_4442;
const CANONNAME_CAPACITY: usize = 256;

#[repr(C)]
pub struct CabiSockaddr {
    family: u16,
    data: [c_char; 14],
}

#[repr(C)]
struct CabiSockaddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
struct CabiSockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
pub struct CabiAddrInfo {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    address_length: c_uint,
    address: *mut CabiSockaddr,
    canonname: *mut c_char,
    next: *mut CabiAddrInfo,
}

#[repr(C)]
struct NumericAddrInfoNode {
    info: CabiAddrInfo,
    magic: u64,
    address: [u8; 28],
    canonname: [c_char; CANONNAME_CAPACITY],
}

#[derive(Clone, Copy)]
struct Address {
    family: c_int,
    bytes: [u8; 16],
}

#[inline]
fn linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
}

/// Allocate the opaque one-page C result owner.
unsafe fn allocate_node() -> *mut NumericAddrInfoNode {
    // SAFETY: this is a fixed anonymous private mapping with no file or
    // caller-owned address. Its page-sized lifetime is released below.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            PAGE_SIZE as i64,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        )
    };
    if linux_error(result) {
        core::ptr::null_mut()
    } else {
        result as usize as *mut NumericAddrInfoNode
    }
}

/// Release the one-page result owner, ignoring a malformed foreign pointer.
unsafe fn release_node(node: *mut NumericAddrInfoNode) {
    if node.is_null() || unsafe { (*node).magic } != NODE_MAGIC {
        return;
    }
    // SAFETY: `node` was allocated by `allocate_node` and its magic guards
    // this leaf's private ownership before releasing exactly one page.
    let _ = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            node as usize as i64,
            PAGE_SIZE as i64,
        )
    };
}

/// Return the length of a C string, capped before a fixed local copy.
unsafe fn c_string_length(value: *const c_char, limit: usize) -> Option<usize> {
    if value.is_null() {
        return None;
    }
    for length in 0..limit {
        // SAFETY: the public C API requires a readable NUL-terminated string.
        if unsafe { *value.add(length) } == 0 {
            return Some(length);
        }
    }
    None
}

unsafe fn parse_numeric_service(service: *const c_char) -> Option<u16> {
    if service.is_null() {
        return Some(0);
    }
    let mut value = 0u32;
    let mut cursor = service as *const u8;
    let mut digits = 0usize;
    loop {
        // SAFETY: the public C API requires a readable NUL-terminated string.
        let byte = unsafe { *cursor };
        if byte == 0 {
            break;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
        if value > u16::MAX as u32 {
            return None;
        }
        digits += 1;
        // SAFETY: a non-NUL byte proves the next C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
    (digits != 0).then_some(value as u16)
}

unsafe fn parse_numeric_node(name: *const c_char, family: c_int, flags: c_int) -> Option<Address> {
    let mut address = Address {
        family: 0,
        bytes: [0; 16],
    };
    if (family == AF_UNSPEC || family == AF_INET || (family == AF_INET6 && flags & AI_V4MAPPED != 0))
        && unsafe { inet_address::inet_pton(AF_INET, name, address.bytes.as_mut_ptr().cast()) } == 1
    {
        if family == AF_INET6 {
            let v4 = address.bytes;
            address.bytes = [0; 16];
            address.bytes[10] = 0xff;
            address.bytes[11] = 0xff;
            address.bytes[12..16].copy_from_slice(&v4[..4]);
            address.family = AF_INET6;
        } else {
            address.family = AF_INET;
        }
        return Some(address);
    }
    if (family == AF_UNSPEC || family == AF_INET6)
        && unsafe { inet_address::inet_pton(AF_INET6, name, address.bytes.as_mut_ptr().cast()) } == 1
    {
        address.family = AF_INET6;
        return Some(address);
    }
    None
}

fn default_node(family: c_int, flags: c_int) -> Address {
    let mut address = Address {
        family: if family == AF_INET { AF_INET } else { AF_INET6 },
        bytes: [0; 16],
    };
    if flags & AI_PASSIVE == 0 {
        if address.family == AF_INET {
            address.bytes[0] = 127;
            address.bytes[3] = 1;
        } else {
            address.bytes[15] = 1;
        }
    }
    address
}

fn service_choices(socktype: c_int, protocol: c_int) -> Result<([(c_int, c_int); 2], usize), c_int> {
    if socktype != 0 && socktype != SOCK_STREAM && socktype != SOCK_DGRAM {
        return Err(EAI_SOCKTYPE);
    }
    if protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Err(EAI_SERVICE);
    }
    if (socktype == SOCK_STREAM && protocol == IPPROTO_UDP)
        || (socktype == SOCK_DGRAM && protocol == IPPROTO_TCP)
    {
        return Err(EAI_SOCKTYPE);
    }
    let mut choices = [(0, 0); 2];
    if socktype == 0 && protocol == 0 {
        choices[0] = (SOCK_STREAM, IPPROTO_TCP);
        choices[1] = (SOCK_DGRAM, IPPROTO_UDP);
        Ok((choices, 2))
    } else {
        let type_ = if socktype != 0 {
            socktype
        } else if protocol == IPPROTO_TCP {
            SOCK_STREAM
        } else {
            SOCK_DGRAM
        };
        let proto = if protocol != 0 {
            protocol
        } else if type_ == SOCK_STREAM {
            IPPROTO_TCP
        } else {
            IPPROTO_UDP
        };
        choices[0] = (type_, proto);
        Ok((choices, 1))
    }
}

unsafe fn append_node(
    first: &mut *mut CabiAddrInfo,
    last: &mut *mut CabiAddrInfo,
    address: Address,
    socktype: c_int,
    protocol: c_int,
    port: u16,
    _flags: c_int,
    canonname: *const c_char,
) -> Result<(), c_int> {
    let node = unsafe { allocate_node() };
    if node.is_null() {
        return Err(EAI_MEMORY);
    }
    // SAFETY: the mapping is one zeroed writable page and the node is smaller.
    unsafe { core::ptr::write_bytes(node.cast::<u8>(), 0, PAGE_SIZE) };
    unsafe { (*node).magic = NODE_MAGIC };
    unsafe {
        // Musl's result nodes do not echo the input hints: ai_flags is an
        // output field and remains zero for these numeric-only records.
        (*node).info.flags = 0;
        (*node).info.family = address.family;
        (*node).info.socktype = socktype;
        (*node).info.protocol = protocol;
        (*node).info.next = core::ptr::null_mut();
        if address.family == AF_INET {
            let socket = (*node).address.as_mut_ptr().cast::<CabiSockaddrIn>();
            *socket = CabiSockaddrIn {
                family: AF_INET as u16,
                port: port.to_be(),
                address: [address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3]],
                zero: [0; 8],
            };
            (*node).info.address_length = core::mem::size_of::<CabiSockaddrIn>() as c_uint;
        } else {
            let socket = (*node).address.as_mut_ptr().cast::<CabiSockaddrIn6>();
            *socket = CabiSockaddrIn6 {
                family: AF_INET6 as u16,
                port: port.to_be(),
                flowinfo: 0,
                address: address.bytes,
                scope_id: 0,
            };
            (*node).info.address_length = core::mem::size_of::<CabiSockaddrIn6>() as c_uint;
        }
        (*node).info.address = (*node).address.as_mut_ptr().cast::<CabiSockaddr>();
        if !canonname.is_null() {
            let length = c_string_length(canonname, CANONNAME_CAPACITY).ok_or(EAI_OVERFLOW)?;
            core::ptr::copy_nonoverlapping(
                canonname,
                (*node).canonname.as_mut_ptr(),
                length + 1,
            );
            (*node).info.canonname = (*node).canonname.as_mut_ptr();
        }
        let info = core::ptr::addr_of_mut!((*node).info);
        if first.is_null() {
            *first = info;
        } else {
            (**last).next = info;
        }
        *last = info;
    }
    Ok(())
}

/// Free a list returned by this leaf's `getaddrinfo`.
#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(mut result: *mut CabiAddrInfo) {
    while !result.is_null() {
        // SAFETY: every selected result begins its page with `CabiAddrInfo`.
        let next = unsafe { (*result).next };
        unsafe { release_node(result.cast::<NumericAddrInfoNode>()) };
        result = next;
    }
}

/// Resolve a numeric node/service without hosts, resolver configuration, or DNS.
#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    name: *const c_char,
    service: *const c_char,
    hints: *const CabiAddrInfo,
    result: *mut *mut CabiAddrInfo,
) -> c_int {
    if result.is_null() {
        return EAI_SYSTEM;
    }
    unsafe { *result = core::ptr::null_mut() };
    if name.is_null() && service.is_null() {
        return EAI_NONAME;
    }
    let (flags, family, socktype, protocol) = if hints.is_null() {
        (0, AF_UNSPEC, 0, 0)
    } else {
        unsafe { ((*hints).flags, (*hints).family, (*hints).socktype, (*hints).protocol) }
    };
    if flags & !AI_SUPPORTED != 0 {
        return EAI_BADFLAGS;
    }
    if family != AF_UNSPEC && family != AF_INET && family != AF_INET6 {
        return EAI_FAMILY;
    }
    let port = match unsafe { parse_numeric_service(service) } {
        Some(port) => port,
        None if flags & AI_NUMERICSERV != 0 => return EAI_NONAME,
        None => return EAI_SERVICE,
    };
    let (choices, choice_count) = match service_choices(socktype, protocol) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let address = if name.is_null() {
        default_node(family, flags)
    } else {
        match unsafe { parse_numeric_node(name, family, flags) } {
            Some(address) => address,
            None => return EAI_NONAME,
        }
    };
    let mut first = core::ptr::null_mut();
    let mut last = core::ptr::null_mut();
    for (index, (selected_type, selected_protocol)) in choices[..choice_count].iter().enumerate() {
        let canonname = if flags & AI_CANONNAME != 0 && index == 0 && !name.is_null() {
            name
        } else {
            core::ptr::null()
        };
        if let Err(error) = unsafe {
            append_node(
                &mut first,
                &mut last,
                address,
                *selected_type,
                *selected_protocol,
                port,
                flags,
                canonname,
            )
        } {
            unsafe { freeaddrinfo(first) };
            return error;
        }
    }
    unsafe { *result = first };
    0
}

unsafe fn copy_text(output: *mut c_char, capacity: usize, source: *const c_char) -> c_int {
    if output.is_null() {
        return 0;
    }
    let length = unsafe { c_string_length(source, CANONNAME_CAPACITY) }.unwrap_or(CANONNAME_CAPACITY);
    if length >= capacity {
        return EAI_OVERFLOW;
    }
    unsafe { core::ptr::copy_nonoverlapping(source, output, length + 1) };
    0
}

unsafe fn write_decimal(output: *mut c_char, capacity: usize, value: u16) -> c_int {
    if output.is_null() {
        return 0;
    }
    let mut text = [0u8; 6];
    let mut number = value;
    let mut cursor = text.len();
    loop {
        cursor -= 1;
        text[cursor] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    let length = text.len() - cursor;
    if length >= capacity {
        return EAI_OVERFLOW;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr().add(cursor).cast::<c_char>(), output, length);
        *output.add(length) = 0;
    }
    0
}

/// Render numeric socket address/service values without reverse DNS or services.
#[no_mangle]
pub unsafe extern "C" fn getnameinfo(
    address: *const CabiSockaddr,
    address_length: c_uint,
    host: *mut c_char,
    host_length: c_uint,
    service: *mut c_char,
    service_length: c_uint,
    flags: c_int,
) -> c_int {
    if address.is_null() {
        return EAI_FAMILY;
    }
    if flags & !NI_SUPPORTED != 0 {
        return EAI_BADFLAGS;
    }
    let family = unsafe { (*address).family as c_int };
    let mut numeric_bytes = [0u8; 16];
    let port = if family == AF_INET {
        if address_length < core::mem::size_of::<CabiSockaddrIn>() as c_uint {
            return EAI_FAMILY;
        }
        let input = address.cast::<CabiSockaddrIn>();
        unsafe { numeric_bytes[..4].copy_from_slice(&(*input).address) };
        unsafe { (*input).port }
    } else if family == AF_INET6 {
        if address_length < core::mem::size_of::<CabiSockaddrIn6>() as c_uint {
            return EAI_FAMILY;
        }
        let input = address.cast::<CabiSockaddrIn6>();
        unsafe { numeric_bytes.copy_from_slice(&(*input).address) };
        unsafe { (*input).port }
    } else {
        return EAI_FAMILY;
    };
    if !host.is_null() {
        if host_length == 0 {
            return EAI_OVERFLOW;
        }
        if flags & NI_NAMEREQD != 0 {
            return EAI_NONAME;
        }
        let mut numeric = [0 as c_char; 46];
        if unsafe { inet_address::inet_ntop(family, numeric_bytes.as_ptr().cast::<c_void>(), numeric.as_mut_ptr(), numeric.len() as c_uint) }.is_null() {
            return EAI_SYSTEM;
        }
        let status = unsafe { copy_text(host, host_length as usize, numeric.as_ptr()) };
        if status != 0 {
            return status;
        }
    }
    if !service.is_null() {
        if service_length == 0 {
            return EAI_OVERFLOW;
        }
        let status = unsafe { write_decimal(service, service_length as usize, u16::from_be(port)) };
        if status != 0 {
            return status;
        }
    }
    0
}

static EAI_BADFLAGS_TEXT: &[u8] = b"Invalid flags\0";
static EAI_NONAME_TEXT: &[u8] = b"Name does not resolve\0";
static EAI_FAMILY_TEXT: &[u8] = b"Unrecognized address family or invalid length\0";
static EAI_SOCKTYPE_TEXT: &[u8] = b"Unrecognized socket type\0";
static EAI_SERVICE_TEXT: &[u8] = b"Unrecognized service\0";
static EAI_MEMORY_TEXT: &[u8] = b"Out of memory\0";
static EAI_SYSTEM_TEXT: &[u8] = b"System error\0";
static EAI_OVERFLOW_TEXT: &[u8] = b"Overflow\0";
static EAI_UNKNOWN_TEXT: &[u8] = b"Unknown error\0";

/// Return the stable error text for the selected numeric `netdb.h` codes.
#[no_mangle]
pub unsafe extern "C" fn gai_strerror(error: c_int) -> *const c_char {
    match error {
        EAI_BADFLAGS => EAI_BADFLAGS_TEXT.as_ptr(),
        EAI_NONAME => EAI_NONAME_TEXT.as_ptr(),
        EAI_FAMILY => EAI_FAMILY_TEXT.as_ptr(),
        EAI_SOCKTYPE => EAI_SOCKTYPE_TEXT.as_ptr(),
        EAI_SERVICE => EAI_SERVICE_TEXT.as_ptr(),
        EAI_MEMORY => EAI_MEMORY_TEXT.as_ptr(),
        EAI_SYSTEM => EAI_SYSTEM_TEXT.as_ptr(),
        EAI_OVERFLOW => EAI_OVERFLOW_TEXT.as_ptr(),
        _ => EAI_UNKNOWN_TEXT.as_ptr(),
    }
    .cast()
}
