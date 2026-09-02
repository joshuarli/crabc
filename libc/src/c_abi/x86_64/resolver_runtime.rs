//! Bounded Linux/x86-64 C resolver runtime.
//!
//! This module is the C-owned resolver boundary. It owns the historical
//! per-thread `__res_state` record, composes the separately selected `h_errno`
//! accessor/object owner, parses fresh bounded snapshots of `/etc/resolv.conf`
//! and `/etc/hosts`, and attaches symbolic results to
//! the existing page-owned `addrinfo` list lifetime.  Numeric and passive
//! `getaddrinfo` cases stay in `numeric_netdb`; they never open a local file
//! or send DNS.  DNS wire validation, timeout, configured-order failover, and
//! UDP-to-TCP fallback remain in the stateless `crabc-core::resolver`
//! transport.  That transport has no resolver configuration, TLS, cache, or
//! C-result ownership, so it does not dilute this C ABI state boundary.
//!
//! The source/behavior oracle is pinned musl 1.2.6, release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT licensed:
//!
//! - `src/network/res_mkquery.c`, `src/network/res_send.c`,
//!   `src/network/res_query.c`, and `src/network/res_querydomain.c` supply
//!   the selected historical resolver spellings; `src/network/res_query.c`
//!   supplies musl's `res_query`/`res_search` weak alias
//!   boundary; `src/network/h_errno.c` is instead owned by the separate
//!   `h_errno` artifact composed by this feature;
//! - `src/network/lookup_name.c` and `lookup_ipliteral.c` establish the
//!   numeric-before-hosts-before-DNS ordering used by `getaddrinfo`; and
//! - `src/network/resolvconf.c` is the configuration/layout source.
//!
//! The deliberately bounded first package supports nameserver, domain/search,
//! and `options ndots`, `timeout`, and `attempts`; `/etc/hosts`; numeric,
//! A/AAAA, and one-response CNAME canonical-name observation; and
//! `res_mkquery`, `res_send`, `res_query`, `res_querydomain`, and `res_search`.
//! It does not expose NSS/plugins, a cache, mDNS, DoH, DoT, DNSSEC, IDNA,
//! reverse/PTR lookup, service databases, EDNS, or resolver hooks.  Those
//! omitted behaviors fail through their named C status surfaces instead of
//! consulting an ambient fallback.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use crabc_core::resolver::{
    self, DnsResponse, ExchangeConfig, NameServer, CLASS_IN, MAX_NAMESERVERS, TYPE_A,
    TYPE_AAAA, TYPE_CNAME,
};

use super::{
    errno, h_errno, inet_address, numeric_netdb::{self, Address, CabiAddrInfo}, raw_syscall,
};

const AF_UNSPEC: c_int = 0;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

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

const EAI_BADFLAGS: c_int = -1;
const EAI_NONAME: c_int = -2;
const EAI_AGAIN: c_int = -3;
const EAI_FAIL: c_int = -4;
const EAI_FAMILY: c_int = -6;
const EAI_SERVICE: c_int = -8;
const EAI_MEMORY: c_int = -10;
const EAI_SYSTEM: c_int = -11;

const HOST_NOT_FOUND: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;

const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;
const EMSGSIZE: c_int = 90;
const EOVERFLOW: c_int = 75;

const MAXNS: usize = 3;
const MAXDNSRCH: usize = 6;
const MAX_FILE_SNAPSHOT: usize = 1024 * 1024;
const DNS_PORT: u16 = 53;
const RES_INIT: usize = 0x0000_0001;
const RES_RECURSE: usize = 0x0000_0040;
const RES_DEFNAMES: usize = 0x0000_0080;
const RES_DNSRCH: usize = 0x0000_0200;
const RES_NOIP6DOTINT: usize = 0x0008_0000;
const RES_DEFAULT: usize = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH | RES_NOIP6DOTINT;
const QUERY: c_int = 0;

const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const O_RDONLY: i64 = 0;
const AT_FDCWD: i64 = -100;
const LINUX_ERRNO_MAX: i64 = 4095;

#[repr(C)]
#[derive(Clone, Copy)]
struct InAddr {
    s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: InAddr,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SortEntry {
    addr: InAddr,
    mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResExt {
    nscount: u16,
    nsmap: [u16; MAXNS],
    nssocks: [c_int; MAXNS],
    nscount6: u16,
    nsinit: u16,
    nsaddrs: [*mut SockaddrIn6; MAXNS],
    initstamp: [u32; 2],
}

#[repr(C)]
union ResUnion {
    pad: [u8; 52],
    ext: ResExt,
}

/// Exact Linux/x86-64 musl `struct __res_state` storage behind `res_state`.
///
/// This remains private Rust implementation detail even though its C layout
/// is public through `<resolv.h>`; C callers obtain it only through
/// [`__res_state`].  Its domain and search pointers always reference the
/// calling thread's inline `defdname` buffer, never a heap/cache allocation.
#[repr(C)]
pub struct ResolverResState {
    retrans: c_int,
    retry: c_int,
    options: c_ulong,
    nscount: c_int,
    nsaddr_list: [SockaddrIn; MAXNS],
    id: u16,
    _id_padding: u16,
    dnsrch: [*mut c_char; MAXDNSRCH + 1],
    defdname: [c_char; 256],
    pfcode: c_ulong,
    /// The `ndots`, `nsort`, `ipv6_unavail`, and remaining bit fields packed
    /// by the installed x86 header.  Only the low four `ndots` bits are used.
    resolver_flags: u32,
    sort_list: [SortEntry; 10],
    qhook: *mut c_void,
    rhook: *mut c_void,
    res_h_errno: c_int,
    vcsock: c_int,
    flags: c_uint,
    u: ResUnion,
}

const ZERO_IN_ADDR: InAddr = InAddr { s_addr: 0 };
const ZERO_SOCKADDR_IN: SockaddrIn = SockaddrIn {
    sin_family: 0,
    sin_port: 0,
    sin_addr: ZERO_IN_ADDR,
    sin_zero: [0; 8],
};
const ZERO_SOCKADDR_IN6: SockaddrIn6 = SockaddrIn6 {
    sin6_family: 0,
    sin6_port: 0,
    sin6_flowinfo: 0,
    sin6_addr: [0; 16],
    sin6_scope_id: 0,
};
const ZERO_SORT_ENTRY: SortEntry = SortEntry {
    addr: ZERO_IN_ADDR,
    mask: 0,
};
const ZERO_RES_EXT: ResExt = ResExt {
    nscount: 0,
    nsmap: [0; MAXNS],
    nssocks: [-1; MAXNS],
    nscount6: 0,
    nsinit: 0,
    nsaddrs: [core::ptr::null_mut(); MAXNS],
    initstamp: [0; 2],
};

#[thread_local]
static mut RESOLVER_RES_STATE: ResolverResState = ResolverResState {
    retrans: 5,
    retry: 2,
    options: 0,
    nscount: 0,
    nsaddr_list: [ZERO_SOCKADDR_IN; MAXNS],
    id: 0,
    _id_padding: 0,
    dnsrch: [core::ptr::null_mut(); MAXDNSRCH + 1],
    defdname: [0; 256],
    pfcode: 0,
    resolver_flags: 0,
    sort_list: [ZERO_SORT_ENTRY; 10],
    qhook: core::ptr::null_mut(),
    rhook: core::ptr::null_mut(),
    res_h_errno: 0,
    vcsock: -1,
    flags: 0,
    u: ResUnion { ext: ZERO_RES_EXT },
};

#[thread_local]
static mut RESOLVER_IPV6_NAMESERVERS: [SockaddrIn6; MAXNS] = [ZERO_SOCKADDR_IN6; MAXNS];

/// Return this resolver feature's selected worker `res_h_errno` storage.
///
/// The separately owned `h_errno` accessor calls this only when the resolver
/// feature is enabled. It keeps resolver-operation status and the public
/// `__res_state()->res_h_errno` field synchronized without making this module
/// define the public `h_errno` object or accessor.
#[inline]
pub(super) unsafe fn resolver_worker_h_errno_location() -> *mut c_int {
    core::ptr::addr_of_mut!(RESOLVER_RES_STATE.res_h_errno)
}

/// Return the calling thread's historical resolver state record.
#[no_mangle]
pub unsafe extern "C" fn __res_state() -> *mut ResolverResState {
    core::ptr::addr_of_mut!(RESOLVER_RES_STATE)
}

#[inline]
unsafe fn set_errno(value: c_int) {
    unsafe { errno::set_errno(value) };
}

#[inline]
unsafe fn set_h_errno(value: c_int) {
    unsafe {
        h_errno::set(value);
        RESOLVER_RES_STATE.res_h_errno = value;
    }
}

#[inline]
unsafe fn current_h_errno() -> c_int {
    unsafe { h_errno::current() }
}

#[inline]
fn raw_error(result: i64) -> Option<c_int> {
    (result < 0 && result >= -LINUX_ERRNO_MAX).then_some((-result) as c_int)
}

struct FileSnapshot {
    data: *mut u8,
    length: usize,
}

impl FileSnapshot {
    unsafe fn release(&mut self) {
        if !self.data.is_null() {
            let _ = unsafe {
                raw_syscall::syscall2(
                    raw_syscall::SYS_MUNMAP,
                    self.data as usize as i64,
                    (MAX_FILE_SNAPSHOT + 1) as i64,
                )
            };
            self.data = core::ptr::null_mut();
            self.length = 0;
        }
    }
}

/// Load one bounded conventional system file into a temporary anonymous map.
///
/// The buffer belongs to the C resolver for one parse only and is unconditionally
/// unmapped before a public call returns; state stores only copied inline data.
unsafe fn load_file(path: *const u8) -> Result<FileSnapshot, c_int> {
    let fd = unsafe {
        raw_syscall::syscall4(raw_syscall::SYS_OPENAT, AT_FDCWD, path as usize as i64, O_RDONLY, 0)
    };
    if let Some(error) = raw_error(fd) {
        return Err(error);
    }
    let map = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            (MAX_FILE_SNAPSHOT + 1) as i64,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        )
    };
    if let Some(error) = raw_error(map) {
        let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, fd) };
        return Err(error);
    }
    let data = map as usize as *mut u8;
    let mut length = 0usize;
    let mut outcome = Ok(());
    loop {
        let read = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READ,
                fd,
                data.wrapping_add(length) as usize as i64,
                (MAX_FILE_SNAPSHOT - length) as i64,
            )
        };
        if let Some(error) = raw_error(read) {
            outcome = Err(error);
            break;
        }
        if read == 0 {
            break;
        }
        length = length.saturating_add(read as usize);
        if length == MAX_FILE_SNAPSHOT {
            let mut byte = 0u8;
            let extra = unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_READ,
                    fd,
                    core::ptr::addr_of_mut!(byte) as usize as i64,
                    1,
                )
            };
            outcome = match raw_error(extra) {
                Some(error) => Err(error),
                None if extra != 0 => Err(EOVERFLOW),
                None => Ok(()),
            };
            break;
        }
    }
    let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, fd) };
    if let Err(error) = outcome {
        let _ = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_MUNMAP,
                data as usize as i64,
                (MAX_FILE_SNAPSHOT + 1) as i64,
            )
        };
        return Err(error);
    }
    unsafe { data.add(length).write(0) };
    Ok(FileSnapshot { data, length })
}

#[inline]
unsafe fn ascii_space(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
}

unsafe fn next_field(cursor: &mut *mut u8) -> *mut c_char {
    let mut value = *cursor;
    while unsafe { ascii_space(value.read()) } {
        value = unsafe { value.add(1) };
    }
    if unsafe { value.read() } == 0 || unsafe { value.read() } == b'#' || unsafe { value.read() } == b';' {
        *cursor = value;
        return core::ptr::null_mut();
    }
    let start = value;
    while unsafe { value.read() } != 0
        && !unsafe { ascii_space(value.read()) }
        && unsafe { value.read() } != b'#'
        && unsafe { value.read() } != b';'
    {
        value = unsafe { value.add(1) };
    }
    if unsafe { value.read() } != 0 {
        unsafe { value.write(0) };
        value = unsafe { value.add(1) };
    }
    *cursor = value;
    start.cast()
}

unsafe fn c_string_length(value: *const c_char, cap: usize) -> Option<usize> {
    if value.is_null() {
        return None;
    }
    for length in 0..cap {
        if unsafe { value.add(length).read() } == 0 {
            return Some(length);
        }
    }
    None
}

unsafe fn ascii_equal(left: *const c_char, right: *const c_char) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let mut index = 0usize;
    loop {
        let mut a = unsafe { left.add(index).read() as u8 };
        let mut b = unsafe { right.add(index).read() as u8 };
        if a.is_ascii_uppercase() {
            a = a.to_ascii_lowercase();
        }
        if b.is_ascii_uppercase() {
            b = b.to_ascii_lowercase();
        }
        if a != b {
            return false;
        }
        if a == 0 {
            return true;
        }
        index = index.saturating_add(1);
    }
}

unsafe fn parse_decimal(text: *const c_char) -> Option<u32> {
    let length = unsafe { c_string_length(text, 16) }?;
    if length == 0 {
        return None;
    }
    let mut value = 0u32;
    for index in 0..length {
        let byte = unsafe { text.add(index).read() as u8 };
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

unsafe fn reset_state() {
    let old_id = unsafe { RESOLVER_RES_STATE.id };
    unsafe {
        RESOLVER_RES_STATE = ResolverResState {
            retrans: 5,
            retry: 2,
            options: (RES_DEFAULT | RES_INIT) as c_ulong,
            nscount: 0,
            nsaddr_list: [ZERO_SOCKADDR_IN; MAXNS],
            id: old_id.wrapping_add(1).max(1),
            _id_padding: 0,
            dnsrch: [core::ptr::null_mut(); MAXDNSRCH + 1],
            defdname: [0; 256],
            pfcode: 0,
            resolver_flags: 1,
            sort_list: [ZERO_SORT_ENTRY; 10],
            qhook: core::ptr::null_mut(),
            rhook: core::ptr::null_mut(),
            res_h_errno: 0,
            vcsock: -1,
            flags: 0,
            u: ResUnion { ext: ZERO_RES_EXT },
        };
        RESOLVER_IPV6_NAMESERVERS = [ZERO_SOCKADDR_IN6; MAXNS];
    }
}

unsafe fn state_add_search(domain: *const c_char) -> bool {
    let state = core::ptr::addr_of_mut!(RESOLVER_RES_STATE);
    let mut count = 0usize;
    while count < MAXDNSRCH && !unsafe { (*state).dnsrch[count] }.is_null() {
        count += 1;
    }
    if count == MAXDNSRCH {
        return false;
    }
    let used = if count == 0 {
        0
    } else {
        unsafe { (*state).dnsrch[count - 1].offset_from((*state).defdname.as_mut_ptr()) as usize }
            .saturating_add(unsafe { c_string_length((*state).dnsrch[count - 1], 256) }.unwrap_or(256))
            .saturating_add(1)
    };
    let length = match unsafe { c_string_length(domain, 254) } {
        Some(length) if length != 0 && used.saturating_add(length + 1) <= 256 => length,
        _ => return false,
    };
    let destination = unsafe { (*state).defdname.as_mut_ptr().add(used) };
    unsafe {
        core::ptr::copy_nonoverlapping(domain, destination, length + 1);
        (*state).dnsrch[count] = destination;
        (*state).dnsrch[count + 1] = core::ptr::null_mut();
    }
    true
}

unsafe fn clear_search() {
    unsafe {
        RESOLVER_RES_STATE.dnsrch = [core::ptr::null_mut(); MAXDNSRCH + 1];
        RESOLVER_RES_STATE.defdname = [0; 256];
    }
}

unsafe fn parse_resolv_conf() {
    let mut snapshot = match unsafe { load_file(b"/etc/resolv.conf\0".as_ptr()) } {
        Ok(snapshot) => snapshot,
        // No resolver file is a valid empty configuration.  Other failures
        // preserve the initialized defaults and make the later DNS operation
        // publish its own error rather than returning a half-filled state.
        Err(_) => return,
    };
    let mut cursor = snapshot.data;
    let end = unsafe { snapshot.data.add(snapshot.length) };
    let mut search_seen = false;
    while cursor < end {
        let line = cursor;
        while cursor < end && unsafe { cursor.read() } != b'\n' {
            cursor = unsafe { cursor.add(1) };
        }
        if cursor < end {
            unsafe { cursor.write(0) };
            cursor = unsafe { cursor.add(1) };
        }
        let mut fields = line;
        let key = unsafe { next_field(&mut fields) };
        if key.is_null() {
            continue;
        }
        if unsafe { ascii_equal(key, b"nameserver\0".as_ptr().cast()) } {
            let address = unsafe { next_field(&mut fields) };
            if address.is_null() || !unsafe { next_field(&mut fields) }.is_null() {
                continue;
            }
            let mut v4 = [0u8; 4];
            if unsafe { inet_address::inet_pton(AF_INET, address, v4.as_mut_ptr().cast()) } == 1
                && unsafe { RESOLVER_RES_STATE.nscount } < MAXNS as c_int
            {
                let index = unsafe { RESOLVER_RES_STATE.nscount as usize };
                unsafe {
                    RESOLVER_RES_STATE.nsaddr_list[index] = SockaddrIn {
                        sin_family: AF_INET as u16,
                        sin_port: DNS_PORT.to_be(),
                        sin_addr: InAddr { s_addr: u32::from_ne_bytes(v4) },
                        sin_zero: [0; 8],
                    };
                    RESOLVER_RES_STATE.nscount += 1;
                }
                continue;
            }
            let mut v6 = [0u8; 16];
            if unsafe { inet_address::inet_pton(AF_INET6, address, v6.as_mut_ptr().cast()) } == 1 {
                let index = unsafe { RESOLVER_RES_STATE.u.ext.nscount6 as usize };
                if index < MAXNS {
                    unsafe {
                        RESOLVER_IPV6_NAMESERVERS[index] = SockaddrIn6 {
                            sin6_family: AF_INET6 as u16,
                            sin6_port: DNS_PORT.to_be(),
                            sin6_flowinfo: 0,
                            sin6_addr: v6,
                            sin6_scope_id: 0,
                        };
                        RESOLVER_RES_STATE.u.ext.nsaddrs[index] =
                            core::ptr::addr_of_mut!(RESOLVER_IPV6_NAMESERVERS[index]);
                        RESOLVER_RES_STATE.u.ext.nscount6 += 1;
                    }
                }
            }
        } else if unsafe { ascii_equal(key, b"search\0".as_ptr().cast()) } {
            unsafe { clear_search() };
            search_seen = true;
            while unsafe { RESOLVER_RES_STATE.dnsrch[MAXDNSRCH - 1] }.is_null() {
                let domain = unsafe { next_field(&mut fields) };
                if domain.is_null() || !unsafe { state_add_search(domain) } {
                    break;
                }
            }
        } else if unsafe { ascii_equal(key, b"domain\0".as_ptr().cast()) } && !search_seen {
            let domain = unsafe { next_field(&mut fields) };
            if !domain.is_null() && unsafe { next_field(&mut fields) }.is_null() {
                unsafe { clear_search() };
                let _ = unsafe { state_add_search(domain) };
            }
        } else if unsafe { ascii_equal(key, b"options\0".as_ptr().cast()) } {
            loop {
                let option = unsafe { next_field(&mut fields) };
                if option.is_null() {
                    break;
                }
                let mut separator = option.cast::<u8>();
                while unsafe { separator.read() } != 0 && unsafe { separator.read() } != b':' {
                    separator = unsafe { separator.add(1) };
                }
                if unsafe { separator.read() } != b':' {
                    continue;
                }
                unsafe { separator.write(0) };
                let value = unsafe { parse_decimal(separator.add(1).cast()) };
                if unsafe { ascii_equal(option, b"ndots\0".as_ptr().cast()) } {
                    if let Some(value) = value {
                        unsafe { RESOLVER_RES_STATE.resolver_flags =
                            (RESOLVER_RES_STATE.resolver_flags & !0xf) | value.min(15) };
                    }
                } else if unsafe { ascii_equal(option, b"timeout\0".as_ptr().cast()) } {
                    if let Some(value) = value {
                        unsafe { RESOLVER_RES_STATE.retrans = value.clamp(1, 30) as c_int };
                    }
                } else if unsafe { ascii_equal(option, b"attempts\0".as_ptr().cast()) } {
                    if let Some(value) = value {
                        unsafe { RESOLVER_RES_STATE.retry = value.clamp(1, 5) as c_int };
                    }
                }
            }
        }
    }
    unsafe { snapshot.release() };
}

/// Initialize the calling thread's bounded C resolver state from
/// `/etc/resolv.conf`.
#[no_mangle]
pub unsafe extern "C" fn res_init() -> c_int {
    unsafe {
        reset_state();
        parse_resolv_conf();
        set_h_errno(0);
    }
    0
}

unsafe fn ensure_initialized() {
    if unsafe { RESOLVER_RES_STATE.options as usize & RES_INIT } == 0 {
        let _ = unsafe { res_init() };
    }
}

unsafe fn c_name_bytes(name: *const c_char, output: &mut [u8]) -> Option<usize> {
    let length = unsafe { c_string_length(name, output.len()) }?;
    if length == 0 || length >= output.len() {
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(name.cast::<u8>(), output.as_mut_ptr(), length) };
    Some(length)
}

unsafe fn make_query(
    operation: c_int,
    name: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    capacity: usize,
) -> Result<c_int, c_int> {
    if operation != QUERY || answer.is_null() || capacity < 12 || class != CLASS_IN as c_int || type_ < 0 {
        return Err(EINVAL);
    }
    unsafe { ensure_initialized() };
    let mut text = [0u8; 256];
    let length = unsafe { c_name_bytes(name, &mut text) }.ok_or(EINVAL)?;
    let output = unsafe { core::slice::from_raw_parts_mut(answer, capacity) };
    let query_id = unsafe { RESOLVER_RES_STATE.id };
    let written = resolver::encode_query(&text[..length], type_ as u16, query_id, output)
        .map_err(|error| error.raw())?;
    Ok(written as c_int)
}

// Pinned musl makes its private query-builder and transport implementations
// hidden strong ELF symbols and exposes their historical spellings as weak
// same-address aliases. It also gives `res_search` the same address as the
// public strong `res_query` entry. Keeping these aliases in assembly avoids a
// forwarding wrapper, which would change pointer identity and ordinary weak-
// override behavior. Resolver-internal callers below use the hidden builder
// and transport names; C consumers use only spellings declared by `<resolv.h>`.
core::arch::global_asm!(
    ".hidden __res_mkquery",
    ".weak res_mkquery",
    ".set res_mkquery, __res_mkquery",
    ".hidden __res_send",
    ".weak res_send",
    ".set res_send, __res_send",
    ".weak res_search",
    ".set res_search, res_query",
);

/// Encode one selected recursive Internet DNS question in caller storage.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn __res_mkquery(
    operation: c_int,
    name: *const c_char,
    class: c_int,
    type_: c_int,
    _data: *const u8,
    _data_length: c_int,
    _new_record: *const u8,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    if answer_length < 0 {
        unsafe { set_errno(EINVAL) };
        return -1;
    }
    match unsafe { make_query(operation, name, class, type_, answer, answer_length as usize) } {
        Ok(length) => length,
        Err(error) => {
            unsafe { set_errno(error) };
            -1
        }
    }
}

/// Encode one uncompressed DNS name in caller storage.
#[no_mangle]
pub unsafe extern "C" fn dn_comp(
    name: *const c_char,
    destination: *mut u8,
    capacity: c_int,
    _pointers: *mut *mut u8,
    _last_pointer: *mut *mut u8,
) -> c_int {
    if capacity < 0 || destination.is_null() {
        unsafe { set_errno(EINVAL) };
        return -1;
    }
    let mut text = [0u8; 256];
    let Some(length) = (unsafe { c_name_bytes(name, &mut text) }) else {
        unsafe { set_errno(EINVAL) };
        return -1;
    };
    let output = unsafe { core::slice::from_raw_parts_mut(destination, capacity as usize) };
    // `encode_query` owns the independently evidenced name encoder.  Strip
    // its fixed header/tail so this C spelling remains caller-buffered.
    let mut query = [0u8; 512];
    let written = match resolver::encode_query(&text[..length], TYPE_A, 1, &mut query) {
        Ok(written) => written,
        Err(error) => {
            unsafe { set_errno(error.raw()) };
            return -1;
        }
    };
    let name_length = written - 16;
    if name_length > output.len() {
        // Pinned musl returns -1 for a destination that cannot hold the
        // complete encoded name without publishing a new errno value.
        return -1;
    }
    output[..name_length].copy_from_slice(&query[12..12 + name_length]);
    name_length as c_int
}

unsafe fn exchange_config() -> Option<ExchangeConfig> {
    unsafe { ensure_initialized() };
    let mut servers = [NameServer::ipv4([127, 0, 0, 1]); MAX_NAMESERVERS];
    let mut count = 0usize;
    let v4_count = unsafe { RESOLVER_RES_STATE.nscount.max(0) as usize }.min(MAXNS);
    for index in 0..v4_count {
        let source = unsafe { RESOLVER_RES_STATE.nsaddr_list[index] };
        if source.sin_family != AF_INET as u16 || count == MAX_NAMESERVERS {
            continue;
        }
        let mut server = NameServer::ipv4(source.sin_addr.s_addr.to_ne_bytes());
        server.port = u16::from_be(source.sin_port);
        servers[count] = server;
        count += 1;
    }
    let v6_count = unsafe { RESOLVER_RES_STATE.u.ext.nscount6 as usize }.min(MAXNS);
    for index in 0..v6_count {
        if count == MAX_NAMESERVERS {
            break;
        }
        let source = unsafe { RESOLVER_RES_STATE.u.ext.nsaddrs[index] };
        if source.is_null() || unsafe { (*source).sin6_family } != AF_INET6 as u16 {
            continue;
        }
        let mut server = NameServer::ipv6(unsafe { (*source).sin6_addr }, unsafe { (*source).sin6_scope_id });
        server.port = u16::from_be(unsafe { (*source).sin6_port });
        servers[count] = server;
        count += 1;
    }
    (count != 0).then_some(ExchangeConfig {
        nameservers: servers,
        nameserver_count: count,
        timeout_ms: unsafe { RESOLVER_RES_STATE.retrans.clamp(1, 30) as u32 }.saturating_mul(1000),
        attempts: unsafe { RESOLVER_RES_STATE.retry.clamp(1, 5) as u8 },
    })
}

unsafe fn resolver_error(error: crabc_core::Errno) {
    unsafe { set_errno(error.raw()) };
    unsafe {
        set_h_errno(if error == crabc_core::Errno::TIMEDOUT || error == crabc_core::Errno::AGAIN {
            TRY_AGAIN
        } else {
            NO_RECOVERY
        });
    }
}

/// Send one caller-built query through nameservers in the calling thread's
/// resolver state.  The shared transport owns only the finite I/O exchange;
/// this wrapper owns C error publication and state-derived configuration.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn __res_send(
    query: *const u8,
    query_length: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    if query.is_null() || answer.is_null() || query_length < 12 || answer_length < 12 {
        unsafe {
            set_errno(EINVAL);
            set_h_errno(NO_RECOVERY);
        }
        return -1;
    }
    let Some(config) = (unsafe { exchange_config() }) else {
        unsafe {
            set_errno(EAGAIN);
            set_h_errno(TRY_AGAIN);
        }
        return -1;
    };
    let query = unsafe { core::slice::from_raw_parts(query, query_length as usize) };
    let answer = unsafe { core::slice::from_raw_parts_mut(answer, answer_length as usize) };
    let query_id = u16::from_be_bytes([query[0], query[1]]);
    match resolver::exchange(&config, query, query_id, answer) {
        Ok(length) => length as c_int,
        Err(error) => {
            unsafe { resolver_error(error) };
            -1
        }
    }
}

unsafe fn query_response(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    if answer.is_null() || answer_length < 12 {
        unsafe {
            set_errno(EINVAL);
            set_h_errno(NO_RECOVERY);
        }
        return -1;
    }
    let mut query = [0u8; 512];
    let length = unsafe {
        __res_mkquery(
            QUERY,
            name,
            class,
            type_,
            core::ptr::null(),
            0,
            core::ptr::null(),
            query.as_mut_ptr(),
            query.len() as c_int,
        )
    };
    if length < 0 {
        unsafe { set_h_errno(NO_RECOVERY) };
        return -1;
    }
    let received = unsafe { __res_send(query.as_ptr(), length, answer, answer_length) };
    if received < 12 {
        return -1;
    }
    let response = unsafe { core::slice::from_raw_parts(answer, received as usize) };
    match response[3] & 0x0f {
        0 if response[6] != 0 || response[7] != 0 => {
            unsafe { set_h_errno(0) };
            received
        }
        0 => {
            unsafe { set_h_errno(NO_DATA) };
            -1
        }
        3 => {
            unsafe { set_h_errno(HOST_NOT_FOUND) };
            -1
        }
        _ => {
            unsafe { set_h_errno(NO_RECOVERY) };
            -1
        }
    }
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn res_query(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    unsafe { query_response(name, class, type_, answer, answer_length) }
}

#[no_mangle]
pub unsafe extern "C" fn res_querydomain(
    name: *const c_char,
    domain: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    if domain.is_null() || unsafe { domain.read() } == 0 {
        return unsafe { query_response(name, class, type_, answer, answer_length) };
    }
    let mut combined = [0 as c_char; 256];
    let Some(name_length) = (unsafe { c_string_length(name, 254) }) else {
        unsafe { set_errno(EINVAL) };
        return -1;
    };
    let Some(domain_length) = (unsafe { c_string_length(domain, 254) }) else {
        unsafe { set_errno(EINVAL) };
        return -1;
    };
    let separator = usize::from(name_length != 0 && unsafe { name.add(name_length - 1).read() } != b'.' as c_char);
    if name_length.saturating_add(separator).saturating_add(domain_length) >= combined.len() {
        unsafe { set_errno(EMSGSIZE) };
        return -1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(name, combined.as_mut_ptr(), name_length);
        if separator != 0 {
            combined[name_length] = b'.' as c_char;
        }
        core::ptr::copy_nonoverlapping(domain, combined.as_mut_ptr().add(name_length + separator), domain_length + 1);
    }
    unsafe { query_response(combined.as_ptr(), class, type_, answer, answer_length) }
}

unsafe fn hosts_lookup(
    name: *const c_char,
    family: c_int,
    choices: &[(c_int, c_int)],
    port: u16,
    flags: c_int,
    first: &mut *mut CabiAddrInfo,
    last: &mut *mut CabiAddrInfo,
) -> Result<bool, c_int> {
    let mut snapshot = match unsafe { load_file(b"/etc/hosts\0".as_ptr()) } {
        Ok(snapshot) => snapshot,
        Err(error) if error == 2 => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut cursor = snapshot.data;
    let end = unsafe { snapshot.data.add(snapshot.length) };
    let mut found = false;
    while cursor < end {
        let line = cursor;
        while cursor < end && unsafe { cursor.read() } != b'\n' {
            cursor = unsafe { cursor.add(1) };
        }
        if cursor < end {
            unsafe { cursor.write(0) };
            cursor = unsafe { cursor.add(1) };
        }
        let mut fields = line;
        let address_text = unsafe { next_field(&mut fields) };
        let canonical = unsafe { next_field(&mut fields) };
        if address_text.is_null() || canonical.is_null() {
            continue;
        }
        let mut matches = unsafe { ascii_equal(name, canonical) };
        while !matches {
            let alias = unsafe { next_field(&mut fields) };
            if alias.is_null() {
                break;
            }
            matches = unsafe { ascii_equal(name, alias) };
        }
        if !matches {
            continue;
        }
        let mut bytes = [0u8; 16];
        let actual_family = if unsafe { inet_address::inet_pton(AF_INET, address_text, bytes.as_mut_ptr().cast()) } == 1 {
            AF_INET
        } else if unsafe { inet_address::inet_pton(AF_INET6, address_text, bytes.as_mut_ptr().cast()) } == 1 {
            AF_INET6
        } else {
            continue;
        };
        let selected = match family {
            AF_UNSPEC => Some(Address { family: actual_family, bytes }),
            selected if selected == actual_family => Some(Address { family: actual_family, bytes }),
            AF_INET6 if actual_family == AF_INET && flags & AI_V4MAPPED != 0 => {
                let mut mapped = [0u8; 16];
                mapped[10] = 0xff;
                mapped[11] = 0xff;
                mapped[12..].copy_from_slice(&bytes[..4]);
                Some(Address { family: AF_INET6, bytes: mapped })
            }
            _ => None,
        };
        if let Some(address) = selected {
            for (choice_index, (socktype, protocol)) in choices.iter().enumerate() {
                let canonname = if !found && choice_index == 0 && flags & AI_CANONNAME != 0 {
                    canonical
                } else {
                    core::ptr::null()
                };
                unsafe {
                    numeric_netdb::append_node(first, last, address, *socktype, *protocol, port, flags, canonname)
                }
                .map_err(|error| error)?;
            }
            found = true;
        }
    }
    unsafe { snapshot.release() };
    Ok(found)
}

unsafe fn lookup_dns_records(
    name: *const c_char,
    type_: u16,
    first: &mut *mut CabiAddrInfo,
    last: &mut *mut CabiAddrInfo,
    choices: &[(c_int, c_int)],
    port: u16,
    flags: c_int,
    canonical: *const c_char,
) -> Result<bool, c_int> {
    let mut query = [0u8; 512];
    let query_length = unsafe {
        make_query(
            QUERY,
            name,
            CLASS_IN as c_int,
            type_ as c_int,
            query.as_mut_ptr(),
            query.len(),
        )
    }
    .map_err(|error| error)?;
    let mut answer = [0u8; 4096];
    let received = unsafe {
        __res_send(
            query.as_ptr(),
            query_length,
            answer.as_mut_ptr(),
            answer.len() as c_int,
        )
    };
    if received < 0 {
        return Ok(false);
    }
    let query_id = u16::from_be_bytes([query[0], query[1]]);
    let name_length = unsafe { c_string_length(name, 255) }.ok_or(EINVAL)?;
    let response = DnsResponse::parse(&answer[..received as usize], unsafe { core::slice::from_raw_parts(name.cast(), name_length) }, type_, query_id)
        .map_err(|error| error.raw())?;
    match response.response_code() {
        0 => {}
        3 => {
            unsafe { set_h_errno(HOST_NOT_FOUND) };
            return Ok(false);
        }
        _ => {
            unsafe { set_h_errno(NO_RECOVERY) };
            return Ok(false);
        }
    }
    let mut found = false;
    let mut cname = [0 as c_char; 256];
    let canonical = match response.rdata_at(TYPE_CNAME, 0, unsafe {
        core::slice::from_raw_parts_mut(cname.as_mut_ptr().cast::<u8>(), cname.len())
    }) {
        Ok(Some(length)) if length < cname.len() => {
            cname[length] = 0;
            cname.as_ptr()
        }
        Ok(_) => canonical,
        Err(error) => return Err(error.raw()),
    };
    for ordinal in 0..32 {
        let mut bytes = [0u8; 16];
        let Some(length) = response.rdata_at(type_, ordinal, &mut bytes).map_err(|error| error.raw())? else {
            break;
        };
        let valid = (type_ == TYPE_A && length == 4) || (type_ == TYPE_AAAA && length == 16);
        if !valid {
            continue;
        }
        let address = Address {
            family: if type_ == TYPE_A { AF_INET } else { AF_INET6 },
            bytes,
        };
        for (choice_index, (socktype, protocol)) in choices.iter().enumerate() {
            let canonname = if !found && choice_index == 0 && flags & AI_CANONNAME != 0 {
                canonical
            } else {
                core::ptr::null()
            };
            unsafe {
                numeric_netdb::append_node(first, last, address, *socktype, *protocol, port, flags, canonname)
            }
            .map_err(|error| error)?;
        }
        found = true;
    }
    if !found {
        unsafe { set_h_errno(NO_DATA) };
    } else {
        unsafe { set_h_errno(0) };
    }
    Ok(found)
}

unsafe fn resolve_symbolic(
    name: *const c_char,
    family: c_int,
    choices: &[(c_int, c_int)],
    port: u16,
    flags: c_int,
    first: &mut *mut CabiAddrInfo,
    last: &mut *mut CabiAddrInfo,
) -> Result<bool, c_int> {
    if unsafe { hosts_lookup(name, family, choices, port, flags, first, last) }? {
        unsafe { set_h_errno(0) };
        return Ok(true);
    }
    unsafe { ensure_initialized() };
    let mut candidate = [0 as c_char; 256];
    let name_length = unsafe { c_string_length(name, 254) }.ok_or(EINVAL)?;
    let absolute = name_length != 0 && unsafe { name.add(name_length - 1).read() } == b'.' as c_char;
    let dots = (0..name_length)
        .filter(|index| unsafe { name.add(*index).read() } == b'.' as c_char)
        .count();
    let ndots = unsafe { RESOLVER_RES_STATE.resolver_flags & 0xf } as usize;
    let search_first = !absolute && dots < ndots;
    let mut try_candidate = |candidate: *const c_char| -> Result<bool, c_int> {
        let mut found = false;
        if family == AF_UNSPEC || family == AF_INET {
            found |= unsafe { lookup_dns_records(candidate, TYPE_A, first, last, choices, port, flags, candidate) }?;
        }
        if family == AF_UNSPEC || family == AF_INET6 {
            found |= unsafe { lookup_dns_records(candidate, TYPE_AAAA, first, last, choices, port, flags, candidate) }?;
        }
        Ok(found)
    };
    if search_first {
        for index in 0..MAXDNSRCH {
            let suffix = unsafe { RESOLVER_RES_STATE.dnsrch[index] };
            if suffix.is_null() {
                break;
            }
            if unsafe { join_domain(name, suffix, &mut candidate) } && try_candidate(candidate.as_ptr())? {
                return Ok(true);
            }
        }
    }
    if try_candidate(name)? {
        return Ok(true);
    }
    if !search_first && !absolute {
        for index in 0..MAXDNSRCH {
            let suffix = unsafe { RESOLVER_RES_STATE.dnsrch[index] };
            if suffix.is_null() {
                break;
            }
            if unsafe { join_domain(name, suffix, &mut candidate) } && try_candidate(candidate.as_ptr())? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

unsafe fn join_domain(name: *const c_char, suffix: *const c_char, output: &mut [c_char; 256]) -> bool {
    let Some(name_length) = (unsafe { c_string_length(name, 254) }) else { return false; };
    let Some(suffix_length) = (unsafe { c_string_length(suffix, 254) }) else { return false; };
    let separator = usize::from(name_length != 0 && unsafe { name.add(name_length - 1).read() } != b'.' as c_char);
    if name_length.saturating_add(separator).saturating_add(suffix_length) >= output.len() {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(name, output.as_mut_ptr(), name_length);
        if separator != 0 {
            output[name_length] = b'.' as c_char;
        }
        core::ptr::copy_nonoverlapping(suffix, output.as_mut_ptr().add(name_length + separator), suffix_length + 1);
    }
    true
}

/// Resolve numeric, `/etc/hosts`, then configured A/AAAA DNS names into the
/// C-owned `addrinfo` pages released by `freeaddrinfo`.
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
    unsafe { result.write(core::ptr::null_mut()) };
    if name.is_null() {
        return unsafe { numeric_netdb::numeric_getaddrinfo(name, service, hints, result) };
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
    let port = match unsafe { numeric_netdb::parse_numeric_service(service) } {
        Some(port) => port,
        None if flags & AI_NUMERICSERV != 0 => return EAI_NONAME,
        None => return EAI_SERVICE,
    };
    let (choices, count) = match numeric_netdb::service_choices(socktype, protocol) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let choices = &choices[..count];
    if unsafe { numeric_netdb::parse_numeric_node(name, family, flags) }.is_some() {
        return unsafe { numeric_netdb::numeric_getaddrinfo(name, service, hints, result) };
    }
    if flags & AI_NUMERICHOST != 0 {
        unsafe { set_h_errno(HOST_NOT_FOUND) };
        return EAI_NONAME;
    }
    if flags & AI_ADDRCONFIG != 0 {
        // The selected C resolver has no interface snapshot policy.  Keep
        // this explicit instead of pretending that an ambient route lookup
        // could decide the public result.
        return EAI_BADFLAGS;
    }
    let mut first = core::ptr::null_mut();
    let mut last = core::ptr::null_mut();
    let resolved = unsafe { resolve_symbolic(name, family, choices, port, flags, &mut first, &mut last) };
    match resolved {
        Ok(true) => {
            unsafe { result.write(first) };
            0
        }
        Ok(false) => {
            unsafe { numeric_netdb::freeaddrinfo(first) };
            match unsafe { current_h_errno() } {
                TRY_AGAIN => EAI_AGAIN,
                NO_RECOVERY => EAI_FAIL,
                _ => EAI_NONAME,
            }
        }
        Err(error) => {
            unsafe { numeric_netdb::freeaddrinfo(first) };
            if error == ENOMEM {
                EAI_MEMORY
            } else if error == EINVAL {
                EAI_FAIL
            } else {
                unsafe { set_errno(error) };
                EAI_SYSTEM
            }
        }
    }
}

// Keep the imported CNAME record type in the source-level boundary.  The
// first package preserves a CNAME's canonical name only when it accompanies
// address records in one validated response; following a CNAME-only chain is
// intentionally deferred with the remaining resolver profile.
const _: u16 = TYPE_CNAME;
