// Legacy resolver APIs.
//
// The name database entry points in m4_network_databases_exports.rs are
// deliberately file-backed.  This layer composes those records with the
// resolver configuration and DNS packet path: numeric and /etc/hosts names
// never require a network request, while names not present there are queried
// from the nameservers in /etc/resolv.conf.  The public state layout follows
// musl's resolv.h ABI even though the implementation only needs a subset of
// the historical fields.

const M4R_AF_UNSPEC: c_int = 0;
const M4R_AF_INET: c_int = 2;
const M4R_AF_INET6: c_int = 10;
const M4R_SOCK_STREAM: c_int = 1;
const M4R_SOCK_DGRAM: c_int = 2;
const M4R_IPPROTO_TCP: c_int = 6;
const M4R_IPPROTO_UDP: c_int = 17;
const M4R_POLLIN: i16 = 0x0001;
const M4R_POLLOUT: i16 = 0x0004;
const M4R_POLLERR: i16 = 0x0008;
const M4R_POLLHUP: i16 = 0x0010;
const M4R_POLLNVAL: i16 = 0x0020;
const M4R_SO_ERROR: c_int = 4;
const M4R_MSG_NOSIGNAL: c_int = 0x4000;
const M4R_DNS_PORT: u16 = 53u16.to_be();
const M4R_DNS_MAX_NAME: usize = 255;
const M4R_DNS_MAX_PACKET: usize = 65535;
const M4R_DNS_QUERY_PACKET: usize = 1024;
const M4R_DNS_ANSWER_PACKET: usize = 65535;
const M4R_MAXNS: usize = 3;
const M4R_MAXDNSRCH: usize = 6;
const M4R_RES_INIT: usize = 0x00000001;
const M4R_RES_RECURSE: usize = 0x00000040;
const M4R_RES_DEFNAMES: usize = 0x00000080;
const M4R_RES_DNSRCH: usize = 0x00000200;
const M4R_RES_NOIP6DOTINT: usize = 0x00080000;
const M4R_RES_DEFAULT: usize =
    M4R_RES_RECURSE | M4R_RES_DEFNAMES | M4R_RES_DNSRCH | M4R_RES_NOIP6DOTINT;
const M4R_QUERY: c_int = 0;
const M4R_NS_CLASS_IN: c_int = 1;
const M4R_NS_TYPE_A: c_int = 1;
const M4R_NS_TYPE_PTR: c_int = 12;
const M4R_NS_TYPE_AAAA: c_int = 28;
const M4R_NS_RCODE_MASK: u16 = 0x000f;
const M4R_NS_RCODE_NXDOMAIN: u16 = 3;
const M4R_EAI_BADFLAGS: c_int = -1;
const M4R_EAI_NONAME: c_int = -2;
const M4R_EAI_AGAIN: c_int = -3;
const M4R_EAI_FAIL: c_int = -4;
const M4R_EAI_FAMILY: c_int = -6;
const M4R_EAI_SOCKTYPE: c_int = -7;
const M4R_EAI_SERVICE: c_int = -8;
const M4R_EAI_MEMORY: c_int = -10;
const M4R_EAI_SYSTEM: c_int = -11;
const M4R_EAI_OVERFLOW: c_int = -12;
const M4R_AI_PASSIVE: c_int = 0x0001;
const M4R_AI_CANONNAME: c_int = 0x0002;
const M4R_AI_NUMERICHOST: c_int = 0x0004;
const M4R_AI_V4MAPPED: c_int = 0x0008;
const M4R_AI_ALL: c_int = 0x0010;
const M4R_AI_ADDRCONFIG: c_int = 0x0020;
const M4R_AI_NUMERICSERV: c_int = 0x0400;
const M4R_NI_NUMERICHOST: c_int = 0x01;
const M4R_NI_NUMERICSERV: c_int = 0x02;
const M4R_NI_NOFQDN: c_int = 0x04;
const M4R_NI_NAMEREQD: c_int = 0x08;
const M4R_NI_DGRAM: c_int = 0x10;
const M4R_NI_NUMERICSCOPE: c_int = 0x100;

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RInAddr {
    s_addr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RSockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: M4RInAddr,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RSockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RSortEntry {
    addr: M4RInAddr,
    mask: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RResExt {
    nscount: u16,
    nsmap: [u16; M4R_MAXNS],
    nssocks: [c_int; M4R_MAXNS],
    nscount6: u16,
    nsinit: u16,
    nsaddrs: [*mut M4RSockaddrIn6; M4R_MAXNS],
    initstamp: [u32; 2],
}

#[repr(C)]
union M4RResUnion {
    pad: [u8; 52],
    ext: M4RResExt,
}

#[repr(C)]
pub struct M4RResState {
    retrans: c_int,
    retry: c_int,
    options: c_ulong,
    nscount: c_int,
    nsaddr_list: [M4RSockaddrIn; M4R_MAXNS],
    id: u16,
    _id_padding: u16,
    dnsrch: [*mut c_char; M4R_MAXDNSRCH + 1],
    defdname: [c_char; 256],
    pfcode: c_ulong,
    resolver_flags: u32,
    sort_list: [M4RSortEntry; 10],
    qhook: *mut c_void,
    rhook: *mut c_void,
    res_h_errno: c_int,
    vcsock: c_int,
    flags: c_uint,
    u: M4RResUnion,
}

const M4R_ZERO_INADDR: M4RInAddr = M4RInAddr { s_addr: 0 };
const M4R_ZERO_SOCKADDR: M4RSockaddrIn = M4RSockaddrIn {
    sin_family: 0,
    sin_port: 0,
    sin_addr: M4R_ZERO_INADDR,
    sin_zero: [0; 8],
};
const M4R_ZERO_SORT: M4RSortEntry = M4RSortEntry {
    addr: M4R_ZERO_INADDR,
    mask: 0,
};
const M4R_ZERO_EXT: M4RResExt = M4RResExt {
    nscount: 0,
    nsmap: [0; M4R_MAXNS],
    nssocks: [-1; M4R_MAXNS],
    nscount6: 0,
    nsinit: 0,
    nsaddrs: [core::ptr::null_mut(); M4R_MAXNS],
    initstamp: [0; 2],
};
const M4R_ZERO_SOCKADDR6: M4RSockaddrIn6 = M4RSockaddrIn6 {
    sin6_family: 0,
    sin6_port: 0,
    sin6_flowinfo: 0,
    sin6_addr: [0; 16],
    sin6_scope_id: 0,
};

#[thread_local]
static mut M4R_RES_STATE: M4RResState = M4RResState {
    retrans: 5,
    retry: 2,
    options: 0,
    nscount: 0,
    nsaddr_list: [M4R_ZERO_SOCKADDR; M4R_MAXNS],
    id: 0,
    _id_padding: 0,
    dnsrch: [core::ptr::null_mut(); M4R_MAXDNSRCH + 1],
    defdname: [0; 256],
    pfcode: 0,
    resolver_flags: 0,
    sort_list: [M4R_ZERO_SORT; 10],
    qhook: core::ptr::null_mut(),
    rhook: core::ptr::null_mut(),
    res_h_errno: 0,
    vcsock: -1,
    flags: 0,
    u: M4RResUnion { ext: M4R_ZERO_EXT },
};

#[thread_local]
static mut M4R_RES_IPV6_NAMESERVERS: [M4RSockaddrIn6; M4R_MAXNS] = [M4R_ZERO_SOCKADDR6; M4R_MAXNS];

#[no_mangle]
pub unsafe extern "C" fn __res_state() -> *mut M4RResState {
    core::ptr::addr_of_mut!(M4R_RES_STATE)
}

#[inline]
unsafe fn m4r_set_h_errno(value: c_int) {
    h_errno = value;
    M4R_RES_STATE.res_h_errno = value;
}

#[inline]
unsafe fn m4r_set_errno_from(result: i64) {
    if result < 0 && result >= -4095 {
        ERRNO = (-result) as c_int;
    }
}

unsafe fn m4r_ascii_equal(left: *const c_char, right: *const c_char) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let mut a = left as *const u8;
    let mut b = right as *const u8;
    loop {
        let mut x = *a;
        let mut y = *b;
        if x >= b'A' && x <= b'Z' { x += b'a' - b'A'; }
        if y >= b'A' && y <= b'Z' { y += b'a' - b'A'; }
        if x != y { return false; }
        if x == 0 { return true; }
        a = a.add(1);
        b = b.add(1);
    }
}

unsafe fn m4r_copy_bytes(dst: *mut u8, dst_len: usize, src: *const u8, src_len: usize) -> bool {
    if dst.is_null() || src.is_null() || src_len >= dst_len {
        return false;
    }
    core::ptr::copy_nonoverlapping(src, dst, src_len);
    *dst.add(src_len) = 0;
    true
}

unsafe fn m4r_copy_cstr(dst: *mut c_char, dst_len: usize, src: *const c_char) -> bool {
    if src.is_null() { return false; }
    m4r_copy_bytes(dst as *mut u8, dst_len, src as *const u8, strlen(src))
}

unsafe fn m4r_parse_decimal(text: *const c_char) -> Option<u32> {
    if text.is_null() || *text == 0 { return None; }
    let mut p = text as *const u8;
    let mut value = 0u32;
    while *p != 0 {
        if *p < b'0' || *p > b'9' { return None; }
        value = value.checked_mul(10)?.checked_add((*p - b'0') as u32)?;
        p = p.add(1);
    }
    Some(value)
}

unsafe fn m4r_name_copy_to_state(state: *mut M4RResState, source: *const c_char) -> Option<*mut c_char> {
    if state.is_null() || source.is_null() { return None; }
    let used = strlen((*state).defdname.as_ptr());
    let length = strlen(source);
    if used.checked_add(length)?.checked_add(1)? >= (*state).defdname.len() { return None; }
    let destination = (*state).defdname.as_mut_ptr().add(used);
    core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length + 1);
    Some(destination)
}

unsafe fn m4r_parse_resolv_conf(state: *mut M4RResState) {
    if state.is_null() { return; }
    (*state).nscount = 0;
    (*state).u = M4RResUnion { ext: M4R_ZERO_EXT };
    (*state).dnsrch = [core::ptr::null_mut(); M4R_MAXDNSRCH + 1];
    (*state).defdname = [0; 256];
    let mut file = M4NdbFile {
        data: core::ptr::null_mut(),
        length: 0,
        position: 0,
        stayopen: false,
    };
    if !m4_ndb_load(b"/etc/resolv.conf\0".as_ptr(), &mut file) {
        return;
    }
    let mut search_count = 0usize;
    loop {
        let line = m4_ndb_next_line(&mut file);
        if line.is_null() { break; }
        let mut cursor = line;
        let key = m4_ndb_field(&mut cursor);
        if key.is_null() { continue; }
        if m4r_ascii_equal(key, b"nameserver\0".as_ptr() as *const c_char) {
            let address = m4_ndb_field(&mut cursor);
            if address.is_null() { continue; }
            let mut bytes = [0u8; 4];
            if inet_pton(M4R_AF_INET, address, bytes.as_mut_ptr() as *mut c_void) == 1
                && (*state).nscount < M4R_MAXNS as c_int
            {
                let slot = (*state).nscount as usize;
                (*state).nsaddr_list[slot] = M4RSockaddrIn {
                    sin_family: M4R_AF_INET as u16,
                    sin_port: M4R_DNS_PORT,
                    sin_addr: M4RInAddr { s_addr: u32::from_ne_bytes(bytes) },
                    sin_zero: [0; 8],
                };
                (*state).nscount += 1;
            } else {
                let mut ipv6 = [0u8; 16];
                let ext_count = (*state).u.ext.nscount6 as usize;
                if inet_pton(M4R_AF_INET6, address, ipv6.as_mut_ptr() as *mut c_void) == 1
                    && ext_count < M4R_MAXNS
                {
                    M4R_RES_IPV6_NAMESERVERS[ext_count] = M4RSockaddrIn6 {
                        sin6_family: M4R_AF_INET6 as u16,
                        sin6_port: M4R_DNS_PORT,
                        sin6_flowinfo: 0,
                        sin6_addr: ipv6,
                        sin6_scope_id: 0,
                    };
                    (*state).u.ext.nsaddrs[ext_count] = core::ptr::addr_of_mut!(M4R_RES_IPV6_NAMESERVERS[ext_count]);
                    (*state).u.ext.nscount6 += 1;
                }
            }
        } else if m4r_ascii_equal(key, b"domain\0".as_ptr() as *const c_char)
            || m4r_ascii_equal(key, b"search\0".as_ptr() as *const c_char)
        {
            if search_count != 0 { continue; }
            while search_count < M4R_MAXDNSRCH {
                let domain = m4_ndb_field(&mut cursor);
                if domain.is_null() { break; }
                if let Some(pointer) = m4r_name_copy_to_state(state, domain) {
                    (*state).dnsrch[search_count] = pointer;
                    search_count += 1;
                } else {
                    break;
                }
            }
            (*state).dnsrch[search_count] = core::ptr::null_mut();
        } else if m4r_ascii_equal(key, b"options\0".as_ptr() as *const c_char) {
            loop {
                let option = m4_ndb_field(&mut cursor);
                if option.is_null() { break; }
                let option_cursor = option as *mut u8;
                let mut name_end = option_cursor;
                while *name_end != 0 && *name_end != b':' { name_end = name_end.add(1); }
                if *name_end == b':' {
                    *name_end = 0;
                    let value = m4r_parse_decimal(name_end.add(1) as *const c_char);
                    if m4r_ascii_equal(option_cursor as *const c_char, b"ndots\0".as_ptr() as *const c_char) {
                        let ndots = value.unwrap_or(1).min(15);
                        (*state).resolver_flags = ((*state).resolver_flags & !0x0f) | ndots;
                    }
                    *name_end = b':';
                }
            }
        }
    }
    m4_ndb_dispose(&mut file);
}

#[no_mangle]
pub unsafe extern "C" fn res_init() -> c_int {
    let state = core::ptr::addr_of_mut!(M4R_RES_STATE);
    (*state).retrans = 5;
    (*state).retry = 2;
    (*state).options = (M4R_RES_DEFAULT | M4R_RES_INIT) as c_ulong;
    (*state).resolver_flags = 1;
    (*state).id = (*state).id.wrapping_add(1);
    if (*state).id == 0 { (*state).id = 1; }
    m4r_parse_resolv_conf(state);
    m4r_set_h_errno(0);
    0
}

unsafe fn m4r_ensure_res_init() -> bool {
    if (M4R_RES_STATE.options as usize & M4R_RES_INIT) == 0 {
        if res_init() != 0 { return false; }
    }
    true
}

unsafe fn m4r_encode_name(name: *const c_char, output: *mut u8, capacity: usize) -> Option<usize> {
    if name.is_null() || output.is_null() || capacity == 0 { return None; }
    let length = strlen(name);
    if length > M4R_DNS_MAX_NAME { return None; }
    let mut p = name as *const u8;
    let end = p.add(length);
    let mut written = 0usize;
    if length == 0 {
        if capacity < 1 { return None; }
        *output = 0;
        return Some(1);
    }
    while p < end {
        let label_start = p;
        while p < end && *p != b'.' { p = p.add(1); }
        let label_length = p.offset_from(label_start) as usize;
        if label_length == 0 || label_length > 63 || written.checked_add(label_length + 2)? > capacity {
            return None;
        }
        *output.add(written) = label_length as u8;
        core::ptr::copy_nonoverlapping(label_start, output.add(written + 1), label_length);
        written += label_length + 1;
        if p < end {
            p = p.add(1);
            if p == end { break; }
        }
    }
    if written >= capacity { return None; }
    *output.add(written) = 0;
    Some(written + 1)
}

unsafe fn m4r_make_query(
    op: c_int,
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    buffer: *mut u8,
    buflen: usize,
) -> c_int {
    if buffer.is_null() || buflen < 12 || dname.is_null() || op != M4R_QUERY {
        ERRNO = EINVAL_VAL;
        return -1;
    }
    if !m4r_ensure_res_init() || class < 0 || class > u16::MAX as c_int || type_ < 0 || type_ > u16::MAX as c_int {
        ERRNO = EINVAL_VAL;
        return -1;
    }
    let mut name_bytes = [0u8; 256];
    let name_length = match m4r_encode_name(dname, name_bytes.as_mut_ptr(), name_bytes.len()) {
        Some(value) => value,
        None => { ERRNO = EMSGSIZE_VAL; return -1; }
    };
    let needed = match 12usize.checked_add(name_length).and_then(|v| v.checked_add(4)) {
        Some(value) => value,
        None => { ERRNO = EMSGSIZE_VAL; return -1; }
    };
    if needed > buflen {
        ERRNO = EMSGSIZE_VAL;
        return -1;
    }
    let id = M4R_RES_STATE.id;
    *buffer.add(0) = (id >> 8) as u8;
    *buffer.add(1) = id as u8;
    let flags = if (M4R_RES_STATE.options as usize & M4R_RES_RECURSE) != 0 { 0x0100u16 } else { 0 };
    *buffer.add(2) = (flags >> 8) as u8;
    *buffer.add(3) = flags as u8;
    *buffer.add(4) = 0; *buffer.add(5) = 1;
    for i in 6..12 { *buffer.add(i) = 0; }
    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), buffer.add(12), name_length);
    let qtail = buffer.add(12 + name_length);
    *qtail = (type_ >> 8) as u8; *qtail.add(1) = type_ as u8;
    *qtail.add(2) = (class >> 8) as u8; *qtail.add(3) = class as u8;
    needed as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn res_mkquery(
    op: c_int,
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    _data: *const u8,
    _datalen: c_int,
    _newrr: *const u8,
    buffer: *mut u8,
    buflen: c_int,
) -> c_int {
    if buflen < 0 { ERRNO = EINVAL_VAL; return -1; }
    m4r_make_query(op, dname, class, type_, buffer, buflen as usize)
}

#[no_mangle]
pub unsafe extern "C" fn dn_comp(
    name: *const c_char,
    dest: *mut u8,
    size: c_int,
    _dnptrs: *mut *mut u8,
    _lastdnptr: *mut *mut u8,
) -> c_int {
    if size < 0 { ERRNO = EINVAL_VAL; return -1; }
    match m4r_encode_name(name, dest, size as usize) {
        Some(length) => length as c_int,
        None => { ERRNO = EMSGSIZE_VAL; -1 }
    }
}

unsafe fn m4r_dns_response_ok(answer: *const u8, length: usize, query_id: u16) -> bool {
    if answer.is_null() || length < 12 { return false; }
    let id = ((*answer as u16) << 8) | (*answer.add(1) as u16);
    let questions = ((*answer.add(4) as u16) << 8) | (*answer.add(5) as u16);
    id == query_id && (*answer.add(2) & 0x80) != 0 && questions != 0
}

#[inline]
unsafe fn m4r_dns_response_truncated(answer: *const u8, length: usize) -> bool {
    !answer.is_null() && length >= 4 && (*answer.add(2) & 0x02) != 0
}

// A nameserver may send unrelated, truncated, or wrong-transaction packets
// before the response for this query.  Keep the UDP socket open and consume
// those packets until the configured deadline; abandoning the socket after
// the first malformed datagram incorrectly skips a valid response from the
// same nameserver.
unsafe fn m4r_dns_udp_exchange(
    fd: c_int,
    answer: *mut u8,
    answer_length: usize,
    query_id: u16,
    timeout_ms: c_int,
) -> c_int {
    if answer.is_null() || answer_length < 12 || timeout_ms <= 0 {
        return -1;
    }
    let start = match m4r_dns_now_millis() {
        Some(value) => value,
        None => return -1,
    };
    let deadline = start.saturating_add(timeout_ms as i64);
    loop {
        if !m4r_dns_wait(fd, M4R_POLLIN, deadline) {
            return -1;
        }
        let received = recvfrom(
            fd,
            answer as *mut c_void,
            answer_length,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if received < 0 {
            if ERRNO == EINTR {
                continue;
            }
            return -1;
        }
        let received_length = received as usize;
        if received_length < 12 || !m4r_dns_response_ok(answer, received_length, query_id) {
            continue;
        }
        return received.min(c_int::MAX as isize) as c_int;
    }
}

// The TCP retry uses a nonblocking socket so a nameserver that accepts a
// connection but never completes it cannot pin the resolver indefinitely.
// Every poll and partial read/write is charged against one monotonic deadline
// derived from the configured UDP retransmission timeout.
unsafe fn m4r_dns_now_millis() -> Option<i64> {
    let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
    if sys_clock_gettime(CLOCK_MONOTONIC, &mut now) < 0 {
        return None;
    }
    Some(
        (now.tv_sec as i64)
            .saturating_mul(1000)
            .saturating_add((now.tv_nsec as i64) / 1_000_000),
    )
}

unsafe fn m4r_dns_remaining_millis(deadline: i64) -> Option<c_int> {
    let now = m4r_dns_now_millis()?;
    if now >= deadline {
        return Some(0);
    }
    Some((deadline - now).min(c_int::MAX as i64) as c_int)
}

unsafe fn m4r_dns_wait(fd: c_int, events: i16, deadline: i64) -> bool {
    loop {
        let timeout = match m4r_dns_remaining_millis(deadline) {
            Some(value) if value > 0 => value,
            _ => return false,
        };
        let mut descriptor = M4PollFd { fd, events, revents: 0 };
        let result = poll(&mut descriptor, 1, timeout);
        if result > 0 {
            return (descriptor.revents & (events | M4R_POLLERR | M4R_POLLHUP | M4R_POLLNVAL)) != 0;
        }
        if result == 0 {
            return false;
        }
        if ERRNO != EINTR {
            return false;
        }
    }
}

unsafe fn m4r_dns_send_all(fd: c_int, buffer: *const u8, length: usize, deadline: i64) -> bool {
    let mut offset = 0usize;
    while offset < length {
        if !matches!(m4r_dns_remaining_millis(deadline), Some(value) if value > 0) {
            return false;
        }
        let result = send(
            fd,
            buffer.add(offset) as *const c_void,
            length - offset,
            M4R_MSG_NOSIGNAL,
        );
        if result > 0 {
            offset = offset.saturating_add(result as usize);
            continue;
        }
        if result == 0 {
            return false;
        }
        if ERRNO == EINTR {
            continue;
        }
        if ERRNO != EAGAIN {
            return false;
        }
        if !m4r_dns_wait(fd, M4R_POLLOUT, deadline) {
            return false;
        }
    }
    true
}

unsafe fn m4r_dns_recv_all(fd: c_int, buffer: *mut u8, length: usize, deadline: i64) -> bool {
    let mut offset = 0usize;
    while offset < length {
        if !matches!(m4r_dns_remaining_millis(deadline), Some(value) if value > 0) {
            return false;
        }
        let result = recv(fd, buffer.add(offset) as *mut c_void, length - offset, 0);
        if result > 0 {
            offset = offset.saturating_add(result as usize);
            continue;
        }
        if result == 0 {
            return false;
        }
        if ERRNO == EINTR {
            continue;
        }
        if ERRNO != EAGAIN {
            return false;
        }
        if !m4r_dns_wait(fd, M4R_POLLIN, deadline) {
            return false;
        }
    }
    true
}

unsafe fn m4r_dns_tcp_exchange(
    family: c_int,
    target: *const sockaddr,
    target_length: c_uint,
    query: *const u8,
    query_length: usize,
    answer: *mut u8,
    answer_length: usize,
    query_id: u16,
    timeout_ms: c_int,
) -> c_int {
    if target.is_null() || query.is_null() || answer.is_null() ||
        query_length > u16::MAX as usize || answer_length < 12 || timeout_ms <= 0 {
        return -1;
    }
    let start = match m4r_dns_now_millis() {
        Some(value) => value,
        None => return -1,
    };
    let deadline = start.saturating_add(timeout_ms as i64);
    let fd = socket(family, M4R_SOCK_STREAM, 0);
    if fd < 0 {
        return -1;
    }
    let old_flags = sys_fcntl(fd, F_GETFL, 0);
    if old_flags < 0 || sys_fcntl(fd, F_SETFL, old_flags | O_NONBLOCK as i64) < 0 {
        close(fd);
        return -1;
    }

    let mut connect_result = sys_connect(fd, target, target_length);
    while connect_result == -(EINTR_VAL as i64) {
        if !m4r_dns_wait(fd, M4R_POLLOUT, deadline) {
            close(fd);
            return -1;
        }
        connect_result = sys_connect(fd, target, target_length);
    }
    if connect_result < 0 && connect_result != -(EINPROGRESS_VAL as i64) &&
        connect_result != -(EALREADY_VAL as i64)
    {
        close(fd);
        return -1;
    }
    if connect_result < 0 {
        if !m4r_dns_wait(fd, M4R_POLLOUT, deadline) {
            close(fd);
            return -1;
        }
        let mut socket_error: c_int = 0;
        let mut option_length = core::mem::size_of::<c_int>() as c_uint;
        if getsockopt(
            fd,
            SOL_SOCKET,
            M4R_SO_ERROR,
            &mut socket_error as *mut c_int as *mut c_void,
            &mut option_length,
        ) != 0 || socket_error != 0 {
            close(fd);
            return -1;
        }
    }

    // DNS-over-TCP frames both directions with a two-byte network-order
    // payload length. Send the header and query separately so no large stack
    // copy is needed; m4r_dns_send_all handles short writes for each part.
    let frame_length = [(query_length >> 8) as u8, query_length as u8];
    if !m4r_dns_send_all(fd, frame_length.as_ptr(), frame_length.len(), deadline) ||
        !m4r_dns_send_all(fd, query, query_length, deadline)
    {
        close(fd);
        return -1;
    }
    let mut response_length_bytes = [0u8; 2];
    if !m4r_dns_recv_all(fd, response_length_bytes.as_mut_ptr(), 2, deadline) {
        close(fd);
        return -1;
    }
    let response_length = ((response_length_bytes[0] as usize) << 8) |
        response_length_bytes[1] as usize;
    if response_length < 12 || response_length > answer_length ||
        response_length > M4R_DNS_MAX_PACKET
    {
        close(fd);
        return -1;
    }
    if !m4r_dns_recv_all(fd, answer, response_length, deadline) {
        close(fd);
        return -1;
    }
    close(fd);
    if !m4r_dns_response_ok(answer, response_length, query_id) ||
        m4r_dns_response_truncated(answer, response_length)
    {
        return -1;
    }
    response_length.min(c_int::MAX as usize) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn res_send(query: *const u8, querylen: c_int, answer: *mut u8, anslen: c_int) -> c_int {
    if query.is_null() || answer.is_null() || querylen < 12 || anslen <= 0 {
        ERRNO = EINVAL_VAL;
        m4r_set_h_errno(3);
        return -1;
    }
    if !m4r_ensure_res_init() {
        m4r_set_h_errno(2);
        return -1;
    }
    let query_id = ((*query as u16) << 8) | (*query.add(1) as u16);
    let query_len = querylen as usize;
    let answer_len = anslen as usize;
    let timeout_ms = (M4R_RES_STATE.retrans.max(1).min(5) * 1000) as c_int;
    let mut index = 0usize;
    while index < M4R_RES_STATE.nscount as usize && index < M4R_MAXNS {
        let fd = socket(M4R_AF_INET, M4R_SOCK_DGRAM, 0);
        if fd < 0 { index += 1; continue; }
        let target = &M4R_RES_STATE.nsaddr_list[index];
        let sent = sendto(
            fd,
            query as *const c_void,
            query_len,
            0,
            target as *const M4RSockaddrIn as *const sockaddr,
            core::mem::size_of::<M4RSockaddrIn>() as c_uint,
        );
        if sent == querylen as isize {
            let received = m4r_dns_udp_exchange(
                fd,
                answer,
                answer_len,
                query_id,
                timeout_ms,
            );
            if received >= 0 {
                if m4r_dns_response_truncated(answer, received as usize) {
                    let tcp_received = m4r_dns_tcp_exchange(
                        M4R_AF_INET,
                        target as *const M4RSockaddrIn as *const sockaddr,
                        core::mem::size_of::<M4RSockaddrIn>() as c_uint,
                        query,
                        query_len,
                        answer,
                        answer_len,
                        query_id,
                        timeout_ms,
                    );
                    close(fd);
                    if tcp_received >= 0 {
                        return tcp_received;
                    }
                } else {
                    close(fd);
                    return received;
                }
            } else {
                close(fd);
            }
        } else {
            close(fd);
        }
        index += 1;
    }
    let mut ipv6_index = 0usize;
    while ipv6_index < M4R_RES_STATE.u.ext.nscount6 as usize && ipv6_index < M4R_MAXNS {
        let fd = socket(M4R_AF_INET6, M4R_SOCK_DGRAM, 0);
        if fd >= 0 {
            let target = &M4R_RES_IPV6_NAMESERVERS[ipv6_index];
            let sent = sendto(
                fd,
                query as *const c_void,
                query_len,
                0,
                target as *const M4RSockaddrIn6 as *const sockaddr,
                core::mem::size_of::<M4RSockaddrIn6>() as c_uint,
            );
            if sent == querylen as isize {
                let received = m4r_dns_udp_exchange(
                    fd,
                    answer,
                    answer_len,
                    query_id,
                    timeout_ms,
                );
                if received >= 0 {
                    if m4r_dns_response_truncated(answer, received as usize) {
                        let tcp_received = m4r_dns_tcp_exchange(
                            M4R_AF_INET6,
                            target as *const M4RSockaddrIn6 as *const sockaddr,
                            core::mem::size_of::<M4RSockaddrIn6>() as c_uint,
                            query,
                            query_len,
                            answer,
                            answer_len,
                            query_id,
                            timeout_ms,
                        );
                        close(fd);
                        if tcp_received >= 0 {
                            return tcp_received;
                        }
                    } else {
                        close(fd);
                        return received;
                    }
                } else {
                    close(fd);
                }
            } else {
                close(fd);
            }
        }
        ipv6_index += 1;
    }
    if ERRNO == 0 { ERRNO = ETIMEDOUT_VAL; }
    m4r_set_h_errno(2);
    -1
}

unsafe fn m4r_query_name(name: *const c_char, class: c_int, type_: c_int, answer: *mut u8, anslen: c_int) -> c_int {
    if name.is_null() || answer.is_null() || anslen <= 0 { ERRNO = EINVAL_VAL; return -1; }
    let mut query = [0u8; M4R_DNS_QUERY_PACKET];
    let query_len = m4r_make_query(M4R_QUERY, name, class, type_, query.as_mut_ptr(), query.len());
    if query_len < 0 { return -1; }
    let result = res_send(query.as_ptr(), query_len, answer, anslen);
    if result < 0 { return -1; }
    if result < 12 { m4r_set_h_errno(3); ERRNO = EMSGSIZE_VAL; return -1; }
    let flags = ((*answer.add(2) as u16) << 8) | (*answer.add(3) as u16);
    let rcode = flags & M4R_NS_RCODE_MASK;
    if rcode == M4R_NS_RCODE_NXDOMAIN {
        m4r_set_h_errno(1);
        return -1;
    } else if rcode != 0 {
        m4r_set_h_errno(3);
        return -1;
    } else {
        let count = ((*answer.add(6) as u16) << 8) | (*answer.add(7) as u16);
        if count == 0 {
            m4r_set_h_errno(4);
            return -1;
        }
        m4r_set_h_errno(0);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn res_query(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    m4r_query_name(name, class, type_, answer, anslen)
}

#[no_mangle]
pub unsafe extern "C" fn res_querydomain(
    name: *const c_char,
    domain: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    if name.is_null() || domain.is_null() { ERRNO = EINVAL_VAL; return -1; }
    let name_len = strlen(name);
    let domain_len = strlen(domain);
    let separator = if name_len != 0 && domain_len != 0 { 1 } else { 0 };
    let total = match name_len.checked_add(domain_len).and_then(|v| v.checked_add(separator)).and_then(|v| v.checked_add(1)) {
        Some(value) if value <= M4R_DNS_MAX_NAME + 1 => value,
        _ => { ERRNO = ENAMETOOLONG_VAL; return -1; }
    };
    let mut combined = [0u8; M4R_DNS_MAX_NAME + 1];
    if name_len != 0 { core::ptr::copy_nonoverlapping(name as *const u8, combined.as_mut_ptr(), name_len); }
    let mut offset = name_len;
    if separator != 0 { combined[offset] = b'.'; offset += 1; }
    if domain_len != 0 { core::ptr::copy_nonoverlapping(domain as *const u8, combined.as_mut_ptr().add(offset), domain_len); offset += domain_len; }
    combined[offset] = 0;
    let _ = total;
    m4r_query_name(combined.as_ptr() as *const c_char, class, type_, answer, anslen)
}

unsafe fn m4r_has_dot(name: *const c_char) -> usize {
    let mut p = name as *const u8;
    let mut count = 0usize;
    while !p.is_null() && *p != 0 { if *p == b'.' { count += 1; } p = p.add(1); }
    count
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn res_search(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    if name.is_null() { ERRNO = EINVAL_VAL; return -1; }
    if !m4r_ensure_res_init() { return -1; }
    let absolute = strlen(name) > 0 && *(name as *const u8).add(strlen(name) - 1) == b'.';
    let ndots = (M4R_RES_STATE.resolver_flags & 0x0f) as usize;
    let dots = m4r_has_dot(name);
    let mut tried = false;
    if absolute || dots >= ndots {
        tried = true;
        let result = res_query(name, class, type_, answer, anslen);
        if result >= 0 || absolute { return result; }
    }
    let mut index = 0usize;
    while index < M4R_MAXDNSRCH && !M4R_RES_STATE.dnsrch[index].is_null() {
        tried = true;
        let result = res_querydomain(name, M4R_RES_STATE.dnsrch[index], class, type_, answer, anslen);
        if result >= 0 { return result; }
        if h_errno == 3 { return -1; }
        index += 1;
    }
    if !tried || !absolute {
        return res_query(name, class, type_, answer, anslen);
    }
    -1
}

#[repr(C)]
#[derive(Copy, Clone)]
struct M4RAddress {
    family: c_int,
    bytes: [u8; 16],
}

unsafe fn m4r_add_address(list: *mut M4RAddress, count: *mut usize, family: c_int, bytes: *const u8) -> bool {
    if list.is_null() || count.is_null() || bytes.is_null() || *count >= 32 { return false; }
    let length = if family == M4R_AF_INET { 4 } else if family == M4R_AF_INET6 { 16 } else { return false };
    let mut i = 0usize;
    while i < *count {
        if (*list.add(i)).family == family && core::slice::from_raw_parts((*list.add(i)).bytes.as_ptr(), length) == core::slice::from_raw_parts(bytes, length) {
            return true;
        }
        i += 1;
    }
    (*list.add(*count)).family = family;
    (*list.add(*count)).bytes = [0; 16];
    core::ptr::copy_nonoverlapping(bytes, (*list.add(*count)).bytes.as_mut_ptr(), length);
    *count += 1;
    true
}

unsafe fn m4r_parse_dns_addresses(answer: *const u8, length: usize, wanted_type: c_int, list: *mut M4RAddress, count: *mut usize) -> bool {
    if answer.is_null() || length < 12 { return false; }
    let mut message = M4NsMsg {
        _msg: core::ptr::null(), _eom: core::ptr::null(), _id: 0, _flags: 0,
        _counts: [0; 4], _sections: [core::ptr::null(); 4], _sect: 0, _rrnum: 0, _msg_ptr: core::ptr::null(),
    };
    if ns_initparse(answer, length.min(c_int::MAX as usize) as c_int, &mut message) != 0 { return false; }
    let mut rr = M4NsRR { name: [0; 1025], type_: 0, rr_class: 0, ttl: 0, rdlength: 0, rdata: core::ptr::null() };
    let mut i = 0;
    while i < message._counts[1] {
        if ns_parserr(&mut message, 1, i as c_int, &mut rr) != 0 { return false; }
        if rr.type_ as c_int == wanted_type && rr.rr_class as c_int == M4R_NS_CLASS_IN {
            if wanted_type == M4R_NS_TYPE_A && rr.rdlength == 4 {
                m4r_add_address(list, count, M4R_AF_INET, rr.rdata);
            } else if wanted_type == M4R_NS_TYPE_AAAA && rr.rdlength == 16 {
                m4r_add_address(list, count, M4R_AF_INET6, rr.rdata);
            }
        }
        i += 1;
    }
    true
}

// getaddrinfo follows the resolver search policy for a bare host name.  A
// direct res_query would only ask for "name." and would never try the
// configured search domains; res_search preserves the absolute/FQDN path and
// applies the existing M4R ndots/search state for relative names.
unsafe fn m4r_lookup_dns(
    name: *const c_char,
    type_: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    res_search(name, M4R_NS_CLASS_IN, type_, answer, answer_length)
}

unsafe fn m4r_lookup_host(name: *const c_char, family: c_int, list: *mut M4RAddress, count: *mut usize) {
    if name.is_null() { return; }
    if family == M4R_AF_UNSPEC || family == M4R_AF_INET {
        let host = gethostbyname2(name, M4R_AF_INET);
        if !host.is_null() && !(*host).h_addr_list.is_null() {
            let mut i = 0usize;
            while !(*(*host).h_addr_list.add(i)).is_null() {
                m4r_add_address(list, count, M4R_AF_INET, *(*host).h_addr_list.add(i) as *const u8);
                i += 1;
            }
        }
    }
    if family == M4R_AF_UNSPEC || family == M4R_AF_INET6 {
        let host = gethostbyname2(name, M4R_AF_INET6);
        if !host.is_null() && !(*host).h_addr_list.is_null() {
            let mut i = 0usize;
            while !(*(*host).h_addr_list.add(i)).is_null() {
                m4r_add_address(list, count, M4R_AF_INET6, *(*host).h_addr_list.add(i) as *const u8);
                i += 1;
            }
        }
    }
    let mut has_v4 = false;
    let mut has_v6 = false;
    let mut existing = 0usize;
    while existing < *count {
        if (*list.add(existing)).family == M4R_AF_INET { has_v4 = true; }
        if (*list.add(existing)).family == M4R_AF_INET6 { has_v6 = true; }
        existing += 1;
    }
    let mut answer = [0u8; M4R_DNS_ANSWER_PACKET];
    if (family == M4R_AF_UNSPEC || family == M4R_AF_INET) && !has_v4 {
        let length = m4r_lookup_dns(name, M4R_NS_TYPE_A, answer.as_mut_ptr(), answer.len() as c_int);
        if length >= 0 { m4r_parse_dns_addresses(answer.as_ptr(), length as usize, M4R_NS_TYPE_A, list, count); }
    }
    if (family == M4R_AF_UNSPEC || family == M4R_AF_INET6) && !has_v6 {
        let length = m4r_lookup_dns(name, M4R_NS_TYPE_AAAA, answer.as_mut_ptr(), answer.len() as c_int);
        if length >= 0 { m4r_parse_dns_addresses(answer.as_ptr(), length as usize, M4R_NS_TYPE_AAAA, list, count); }
    }
}

#[repr(C)]
pub struct M4RAddrInfoNode {
    ai_flags: c_int,
    ai_family: c_int,
    ai_socktype: c_int,
    ai_protocol: c_int,
    ai_addrlen: c_uint,
    ai_addr: *mut sockaddr,
    ai_canonname: *mut c_char,
    ai_next: *mut M4RAddrInfoNode,
    address: [u8; 28],
    canonname: [c_char; 256],
}

unsafe fn m4r_append_node(
    first: *mut *mut M4RAddrInfoNode,
    last: *mut *mut M4RAddrInfoNode,
    address: *const M4RAddress,
    socktype: c_int,
    protocol: c_int,
    port: u16,
    flags: c_int,
    canon: *const c_char,
) -> c_int {
    let node = calloc(1, core::mem::size_of::<M4RAddrInfoNode>()) as *mut M4RAddrInfoNode;
    if node.is_null() { return M4R_EAI_MEMORY; }
    (*node).ai_flags = flags;
    (*node).ai_family = (*address).family;
    (*node).ai_socktype = socktype;
    (*node).ai_protocol = protocol;
    (*node).ai_next = core::ptr::null_mut();
    if (*address).family == M4R_AF_INET {
        let storage = (*node).address.as_mut_ptr() as *mut M4RSockaddrIn;
        let mut v4 = [0u8; 4];
        core::ptr::copy_nonoverlapping((*address).bytes.as_ptr(), v4.as_mut_ptr(), 4);
        *storage = M4RSockaddrIn {
            sin_family: M4R_AF_INET as u16,
            sin_port: port,
            sin_addr: M4RInAddr { s_addr: u32::from_ne_bytes(v4) },
            sin_zero: [0; 8],
        };
        (*node).ai_addrlen = core::mem::size_of::<M4RSockaddrIn>() as c_uint;
    } else {
        let storage = (*node).address.as_mut_ptr() as *mut M4RSockaddrIn6;
        *storage = M4RSockaddrIn6 {
            sin6_family: M4R_AF_INET6 as u16,
            sin6_port: port,
            sin6_flowinfo: 0,
            sin6_addr: (*address).bytes,
            sin6_scope_id: 0,
        };
        (*node).ai_addrlen = core::mem::size_of::<M4RSockaddrIn6>() as c_uint;
    }
    (*node).ai_addr = (*node).address.as_mut_ptr() as *mut sockaddr;
    if !canon.is_null() && !(*canon as u8 == 0) {
        if !m4r_copy_cstr((*node).canonname.as_mut_ptr(), (*node).canonname.len(), canon) {
            free(node as *mut c_void);
            return M4R_EAI_OVERFLOW;
        }
        (*node).ai_canonname = (*node).canonname.as_mut_ptr();
    }
    if (*first).is_null() { *first = node; } else { (**last).ai_next = node; }
    *last = node;
    0
}

#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(mut info: *mut M4RAddrInfoNode) {
    while !info.is_null() {
        let next = (*info).ai_next;
        free(info as *mut c_void);
        info = next;
    }
}

unsafe fn m4r_service_choices(
    service: *const c_char,
    hints: *const M4RAddrInfo,
    choices: *mut [(c_int, c_int, u16); 2],
) -> Result<usize, c_int> {
    let mut count = 0usize;
    let socktype = if hints.is_null() { 0 } else { (*hints).ai_socktype };
    let protocol = if hints.is_null() { 0 } else { (*hints).ai_protocol };
    if socktype != 0 && socktype != M4R_SOCK_STREAM && socktype != M4R_SOCK_DGRAM { return Err(M4R_EAI_SOCKTYPE); }
    if protocol != 0 && protocol != M4R_IPPROTO_TCP && protocol != M4R_IPPROTO_UDP { return Err(M4R_EAI_SERVICE); }
    if socktype == M4R_SOCK_STREAM && protocol == M4R_IPPROTO_UDP { return Err(M4R_EAI_SOCKTYPE); }
    if socktype == M4R_SOCK_DGRAM && protocol == M4R_IPPROTO_TCP { return Err(M4R_EAI_SOCKTYPE); }
    if service.is_null() {
        if protocol != 0 || socktype != 0 {
            let selected_type = if socktype != 0 { socktype } else if protocol == M4R_IPPROTO_TCP { M4R_SOCK_STREAM } else { M4R_SOCK_DGRAM };
            let selected_protocol = if protocol != 0 { protocol } else if selected_type == M4R_SOCK_STREAM { M4R_IPPROTO_TCP } else { M4R_IPPROTO_UDP };
            (*choices)[0] = (selected_type, selected_protocol, 0);
            return Ok(1);
        }
        (*choices)[0] = (M4R_SOCK_STREAM, M4R_IPPROTO_TCP, 0);
        (*choices)[1] = (M4R_SOCK_DGRAM, M4R_IPPROTO_UDP, 0);
        return Ok(2);
    }
    if let Some(number) = m4r_parse_decimal(service) {
        if number > u16::MAX as u32 { return Err(M4R_EAI_SERVICE); }
        if socktype != 0 || protocol != 0 {
            let selected_type = if socktype != 0 { socktype } else if protocol == M4R_IPPROTO_TCP { M4R_SOCK_STREAM } else { M4R_SOCK_DGRAM };
            let selected_protocol = if protocol != 0 { protocol } else if selected_type == M4R_SOCK_STREAM { M4R_IPPROTO_TCP } else { M4R_IPPROTO_UDP };
            (*choices)[0] = (selected_type, selected_protocol, (number as u16).to_be());
            return Ok(1);
        }
        (*choices)[0] = (M4R_SOCK_STREAM, M4R_IPPROTO_TCP, (number as u16).to_be());
        (*choices)[1] = (M4R_SOCK_DGRAM, M4R_IPPROTO_UDP, (number as u16).to_be());
        return Ok(2);
    }
    if !hints.is_null() && ((*hints).ai_flags & M4R_AI_NUMERICSERV) != 0 { return Err(M4R_EAI_NONAME); }
    let tcp = b"tcp\0".as_ptr() as *const c_char;
    let udp = b"udp\0".as_ptr() as *const c_char;
    if socktype == 0 && protocol == 0 {
        let tcp_entry = getservbyname(service, tcp);
        if !tcp_entry.is_null() { (*choices)[count] = (M4R_SOCK_STREAM, M4R_IPPROTO_TCP, (*tcp_entry).s_port as u16); count += 1; }
        let udp_entry = getservbyname(service, udp);
        if !udp_entry.is_null() { (*choices)[count] = (M4R_SOCK_DGRAM, M4R_IPPROTO_UDP, (*udp_entry).s_port as u16); count += 1; }
    } else {
        let selected_type = if socktype != 0 { socktype } else if protocol == M4R_IPPROTO_TCP { M4R_SOCK_STREAM } else { M4R_SOCK_DGRAM };
        let selected_protocol = if protocol != 0 { protocol } else if selected_type == M4R_SOCK_STREAM { M4R_IPPROTO_TCP } else { M4R_IPPROTO_UDP };
        let proto = if selected_protocol == M4R_IPPROTO_TCP { tcp } else { udp };
        let entry = getservbyname(service, proto);
        if !entry.is_null() { (*choices)[0] = (selected_type, selected_protocol, (*entry).s_port as u16); count = 1; }
    }
    if count == 0 { Err(M4R_EAI_SERVICE) } else { Ok(count) }
}

// Keep this private Rust type in lockstep with the public netdb.h layout.
#[repr(C)]
pub struct M4RAddrInfo {
    ai_flags: c_int,
    ai_family: c_int,
    ai_socktype: c_int,
    ai_protocol: c_int,
    ai_addrlen: c_uint,
    ai_addr: *mut sockaddr,
    ai_canonname: *mut c_char,
    ai_next: *mut M4RAddrInfo,
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    name: *const c_char,
    service: *const c_char,
    hints: *const M4RAddrInfo,
    result: *mut *mut M4RAddrInfo,
) -> c_int {
    if result.is_null() { return M4R_EAI_SYSTEM; }
    *result = core::ptr::null_mut();
    if name.is_null() && service.is_null() { return M4R_EAI_NONAME; }
    let flags = if hints.is_null() { 0 } else { (*hints).ai_flags };
    if flags & !(M4R_AI_PASSIVE | M4R_AI_CANONNAME | M4R_AI_NUMERICHOST | M4R_AI_V4MAPPED | M4R_AI_ALL | M4R_AI_ADDRCONFIG | M4R_AI_NUMERICSERV) != 0 { return M4R_EAI_BADFLAGS; }
    let family = if hints.is_null() { M4R_AF_UNSPEC } else { (*hints).ai_family };
    if family != M4R_AF_UNSPEC && family != M4R_AF_INET && family != M4R_AF_INET6 { return M4R_EAI_FAMILY; }
    let mut choices = [(0, 0, 0u16); 2];
    let choice_count = match m4r_service_choices(service, hints, &mut choices) { Ok(value) => value, Err(error) => return error };
    let mut addresses = [M4RAddress { family: 0, bytes: [0; 16] }; 32];
    let mut address_count = 0usize;
    let mut canon: *const c_char = core::ptr::null();
    if name.is_null() {
        let mut address = M4RAddress { family: if family == M4R_AF_INET { M4R_AF_INET } else { M4R_AF_INET6 }, bytes: [0; 16] };
        if flags & M4R_AI_PASSIVE == 0 {
            if address.family == M4R_AF_INET { address.bytes[0..4].copy_from_slice(&[127, 0, 0, 1]); }
            else { address.bytes[15] = 1; }
        }
        addresses[0] = address;
        address_count = 1;
    } else {
        let mut numeric = M4RAddress { family: 0, bytes: [0; 16] };
        let mut numeric_ok = false;
        if family == M4R_AF_UNSPEC || family == M4R_AF_INET || (family == M4R_AF_INET6 && (flags & M4R_AI_V4MAPPED) != 0) {
            if inet_pton(M4R_AF_INET, name, numeric.bytes.as_mut_ptr() as *mut c_void) == 1 { numeric.family = M4R_AF_INET; numeric_ok = true; }
        }
        if !numeric_ok && (family == M4R_AF_UNSPEC || family == M4R_AF_INET6) {
            if inet_pton(M4R_AF_INET6, name, numeric.bytes.as_mut_ptr() as *mut c_void) == 1 { numeric.family = M4R_AF_INET6; numeric_ok = true; }
        }
        if numeric_ok {
            addresses[0] = numeric;
            address_count = 1;
            canon = name;
        } else if flags & M4R_AI_NUMERICHOST != 0 {
            return M4R_EAI_NONAME;
        } else {
            m4r_lookup_host(name, family, addresses.as_mut_ptr(), &mut address_count);
            if address_count == 0 {
                return match h_errno {
                    2 => M4R_EAI_AGAIN,
                    3 => M4R_EAI_FAIL,
                    _ => M4R_EAI_NONAME,
                };
            }
            canon = name;
        }
    }
    if family == M4R_AF_INET6 && address_count > 0 {
        if (flags & M4R_AI_V4MAPPED) != 0 && (flags & M4R_AI_ALL) == 0 {
            let mut has_v6 = false;
            let mut i = 0usize;
            while i < address_count {
                if addresses[i].family == M4R_AF_INET6 { has_v6 = true; break; }
                i += 1;
            }
            if has_v6 {
                let mut kept = 0usize;
                i = 0;
                while i < address_count {
                    if addresses[i].family == M4R_AF_INET6 {
                        addresses[kept] = addresses[i];
                        kept += 1;
                    }
                    i += 1;
                }
                address_count = kept;
            }
        }
        let mut converted = [M4RAddress { family: 0, bytes: [0; 16] }; 32];
        let mut converted_count = 0usize;
        let mut i = 0usize;
        while i < address_count {
            if addresses[i].family == M4R_AF_INET6 || (addresses[i].family == M4R_AF_INET && (flags & M4R_AI_V4MAPPED) != 0) {
                let mut value = addresses[i];
                if value.family == M4R_AF_INET { value.family = M4R_AF_INET6; value.bytes = [0; 16]; value.bytes[10] = 0xff; value.bytes[11] = 0xff; value.bytes[12..16].copy_from_slice(&addresses[i].bytes[0..4]); }
                converted[converted_count] = value; converted_count += 1;
            }
            i += 1;
        }
        addresses = converted;
        address_count = converted_count;
        if address_count == 0 { return M4R_EAI_NONAME; }
    }
    let mut first: *mut M4RAddrInfoNode = core::ptr::null_mut();
    let mut last: *mut M4RAddrInfoNode = core::ptr::null_mut();
    let mut i = 0usize;
    while i < address_count {
        let mut j = 0usize;
        while j < choice_count {
            let node_canon = if (flags & M4R_AI_CANONNAME) != 0 && first.is_null() { canon } else { core::ptr::null() };
            let code = m4r_append_node(&mut first, &mut last, &addresses[i], choices[j].0, choices[j].1, choices[j].2, flags, node_canon);
            if code != 0 { freeaddrinfo(first); return code; }
            j += 1;
        }
        i += 1;
    }
    *result = first as *mut M4RAddrInfo;
    0
}

unsafe fn m4r_reverse_name(address: *const u8, family: c_int, output: *mut u8, capacity: usize) -> bool {
    if address.is_null() || output.is_null() || capacity < 1 { return false; }
    let mut offset = 0usize;
    if family == M4R_AF_INET {
        let mut i = 4usize;
        while i > 0 {
            i -= 1;
            let (digits, length) = format_u64(*address.add(i) as u64);
            if offset + length + 1 >= capacity { return false; }
            core::ptr::copy_nonoverlapping(digits.as_ptr(), output.add(offset), length); offset += length;
            *output.add(offset) = b'.'; offset += 1;
        }
        let suffix = b"in-addr.arpa\0";
        if offset + suffix.len() > capacity { return false; }
        core::ptr::copy_nonoverlapping(suffix.as_ptr(), output.add(offset), suffix.len());
        true
    } else {
        let mut i = 16usize;
        while i > 0 {
            i -= 1;
            let byte = *address.add(i);
            for nibble in [byte & 0x0f, byte >> 4] {
                if offset + 2 >= capacity { return false; }
                *output.add(offset) = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 }; offset += 1;
                *output.add(offset) = b'.'; offset += 1;
            }
        }
        let suffix = b"ip6.arpa\0";
        if offset + suffix.len() > capacity { return false; }
        core::ptr::copy_nonoverlapping(suffix.as_ptr(), output.add(offset), suffix.len());
        true
    }
}

unsafe fn m4r_dns_ptr(address: *const u8, family: c_int, output: *mut c_char, capacity: usize) -> bool {
    let mut reverse = [0u8; 80];
    if !m4r_reverse_name(address, family, reverse.as_mut_ptr(), reverse.len()) { return false; }
    let mut answer = [0u8; M4R_DNS_ANSWER_PACKET];
    let length = res_query(reverse.as_ptr() as *const c_char, M4R_NS_CLASS_IN, M4R_NS_TYPE_PTR, answer.as_mut_ptr(), answer.len() as c_int);
    if length < 0 { return false; }
    let mut message = M4NsMsg {
        _msg: core::ptr::null(), _eom: core::ptr::null(), _id: 0, _flags: 0,
        _counts: [0; 4], _sections: [core::ptr::null(); 4], _sect: 0, _rrnum: 0, _msg_ptr: core::ptr::null(),
    };
    if ns_initparse(answer.as_ptr(), length, &mut message) != 0 { return false; }
    let mut rr = M4NsRR { name: [0; 1025], type_: 0, rr_class: 0, ttl: 0, rdlength: 0, rdata: core::ptr::null() };
    let mut i = 0;
    while i < message._counts[1] {
        if ns_parserr(&mut message, 1, i as c_int, &mut rr) != 0 { return false; }
        if rr.type_ as c_int == M4R_NS_TYPE_PTR && rr.rr_class as c_int == M4R_NS_CLASS_IN {
            let eom = answer.as_ptr().add(length as usize);
            return ns_name_uncompress(answer.as_ptr(), eom, rr.rdata, output, capacity) >= 0;
        }
        i += 1;
    }
    false
}

unsafe fn m4r_copy_result(output: *mut c_char, output_len: usize, source: *const c_char, nofqdn: bool) -> c_int {
    if output.is_null() || output_len == 0 { return M4R_EAI_OVERFLOW; }
    let mut length = strlen(source);
    if nofqdn {
        let mut i = 0usize;
        while i < length { if *source.add(i) as u8 == b'.' { length = i; break; } i += 1; }
    }
    if length + 1 > output_len { return M4R_EAI_OVERFLOW; }
    core::ptr::copy_nonoverlapping(source as *const u8, output as *mut u8, length);
    *output.add(length) = 0;
    0
}

unsafe fn m4r_numeric_service(port: u16, output: *mut c_char, output_len: usize) -> c_int {
    let host_order = u16::from_be(port) as u32;
    let (digits, length) = format_u64(host_order as u64);
    if output.is_null() || length + 1 > output_len { return M4R_EAI_OVERFLOW; }
    core::ptr::copy_nonoverlapping(digits.as_ptr(), output as *mut u8, length);
    *output.add(length) = 0;
    0
}

#[no_mangle]
pub unsafe extern "C" fn getnameinfo(
    address: *const sockaddr,
    address_len: c_uint,
    host: *mut c_char,
    host_len: c_uint,
    service: *mut c_char,
    service_len: c_uint,
    flags: c_int,
) -> c_int {
    if address.is_null() { return M4R_EAI_FAMILY; }
    let allowed = M4R_NI_NOFQDN | M4R_NI_NUMERICHOST | M4R_NI_NAMEREQD | M4R_NI_NUMERICSERV | M4R_NI_NUMERICSCOPE;
    if flags & !allowed != 0 { return M4R_EAI_BADFLAGS; }
    let family = (*address).sa_family as c_int;
    let (bytes, port, expected, scope) = if family == M4R_AF_INET {
        let input = address as *const M4RSockaddrIn;
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&(*input).sin_addr.s_addr.to_ne_bytes());
        (bytes, (*input).sin_port, core::mem::size_of::<M4RSockaddrIn>() as c_uint, 0u32)
    } else if family == M4R_AF_INET6 {
        let input = address as *const M4RSockaddrIn6;
        ((*input).sin6_addr, (*input).sin6_port, core::mem::size_of::<M4RSockaddrIn6>() as c_uint, (*input).sin6_scope_id)
    } else { return M4R_EAI_FAMILY; };
    if address_len < expected { return M4R_EAI_FAMILY; }
    if !host.is_null() {
        if host_len == 0 { return M4R_EAI_OVERFLOW; }
        let mut numeric = [0 as c_char; 64];
        if inet_ntop(family, bytes.as_ptr() as *const c_void, numeric.as_mut_ptr(), numeric.len() as u32).is_null() { return M4R_EAI_SYSTEM; }
        if family == M4R_AF_INET6 && scope != 0 {
            let mut interface = [0 as c_char; 16];
            let scope_name = if (flags & M4R_NI_NUMERICSCOPE) == 0 {
                if_indextoname(scope, interface.as_mut_ptr())
            } else { core::ptr::null_mut() };
            let suffix = if !scope_name.is_null() { scope_name as *const c_char } else { core::ptr::null() };
            let base_len = strlen(numeric.as_ptr());
            if base_len + 2 >= numeric.len() { return M4R_EAI_OVERFLOW; }
            *numeric.as_mut_ptr().add(base_len) = b'%' as c_char;
            if !suffix.is_null() {
                let suffix_len = strlen(suffix);
                if base_len + suffix_len + 2 > numeric.len() { return M4R_EAI_OVERFLOW; }
                core::ptr::copy_nonoverlapping(suffix as *const u8, numeric.as_mut_ptr().add(base_len + 1) as *mut u8, suffix_len + 1);
            } else {
                let (digits, digits_len) = format_u64(scope as u64);
                if base_len + digits_len + 2 > numeric.len() { return M4R_EAI_OVERFLOW; }
                core::ptr::copy_nonoverlapping(digits.as_ptr(), numeric.as_mut_ptr().add(base_len + 1) as *mut u8, digits_len);
                *numeric.as_mut_ptr().add(base_len + digits_len + 1) = 0;
            }
        }
        let mut name = [0 as c_char; 1025];
        let mut have_name = false;
        if flags & M4R_NI_NUMERICHOST == 0 {
            let entry = gethostbyaddr(bytes.as_ptr() as *const c_void, if family == M4R_AF_INET { 4 } else { 16 }, family);
            if !entry.is_null() && !(*entry).h_name.is_null() {
                if m4r_copy_result(name.as_mut_ptr(), name.len(), (*entry).h_name, (flags & M4R_NI_NOFQDN) != 0) == 0 { have_name = true; }
            }
            if !have_name && m4r_dns_ptr(bytes.as_ptr(), family, name.as_mut_ptr(), name.len()) { have_name = true; }
        }
        if !have_name {
            if flags & M4R_NI_NAMEREQD != 0 {
                return match h_errno {
                    2 => M4R_EAI_AGAIN,
                    3 => M4R_EAI_FAIL,
                    _ => M4R_EAI_NONAME,
                };
            }
            if m4r_copy_result(host, host_len as usize, numeric.as_mut_ptr(), false) != 0 { return M4R_EAI_OVERFLOW; }
        } else if m4r_copy_result(host, host_len as usize, name.as_mut_ptr(), false) != 0 { return M4R_EAI_OVERFLOW; }
    }
    if !service.is_null() {
        if service_len == 0 { return M4R_EAI_OVERFLOW; }
        if flags & M4R_NI_NUMERICSERV == 0 {
            let protocol = if flags & M4R_NI_DGRAM != 0 { b"udp\0".as_ptr() } else { b"tcp\0".as_ptr() };
            let entry = getservbyport(port as c_int, protocol as *const c_char);
            if !entry.is_null() && !(*entry).s_name.is_null() {
                if m4r_copy_result(service, service_len as usize, (*entry).s_name, false) != 0 { return M4R_EAI_OVERFLOW; }
            } else if m4r_numeric_service(port, service, service_len as usize) != 0 { return M4R_EAI_OVERFLOW; }
        } else if m4r_numeric_service(port, service, service_len as usize) != 0 { return M4R_EAI_OVERFLOW; }
    }
    0
}
