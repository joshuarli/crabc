// M4 resolver compatibility globals and IPv6 constants.
//
// The resolver implementation grows independently, but these names have
// stable, observable contracts today: IPv6 callers may pass the exported
// all-zero and loopback objects to socket APIs, while legacy resolver callers
// use `h_errno` and its accessor to retain an error across helper calls.

#[repr(C)]
pub struct M4In6Addr {
    pub s6_addr: [u8; 16],
}

#[no_mangle]
pub static in6addr_any: M4In6Addr = M4In6Addr { s6_addr: [0; 16] };
#[no_mangle]
pub static in6addr_loopback: M4In6Addr = M4In6Addr {
    s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
};

#[no_mangle]
pub static mut h_errno: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn __h_errno_location() -> *mut c_int {
    &raw mut h_errno
}

// Linux interface-name APIs.  The two point lookups use the kernel's ioctl
// interface, while if_nameindex uses the rtnetlink link dump so that every
// interface currently present in the namespace is returned (including links
// without an address).  Keep the wire layouts local: these are Linux UAPI
// layouts, not the public C `struct ifreq` ABI.

const M4_IF_NAMESIZE: usize = 16;
const M4_IFREQ_SIZE: usize = 40;
const M4_IFR_INDEX_OFFSET: usize = 16;
const M4_SIOCGIFNAME: u32 = 0x8910;
const M4_SIOCGIFINDEX: u32 = 0x8933;
const M4_AF_NETLINK: c_int = 16;
const M4_NETLINK_ROUTE: c_int = 0;
const M4_SOCK_RAW: c_int = 3;
const M4_SOCK_CLOEXEC: c_int = 0x80000;
const M4_NLM_F_REQUEST: u16 = 1;
const M4_NLM_F_DUMP: u16 = 0x300;
const M4_NLMSG_NOOP: u16 = 1;
const M4_NLMSG_ERROR: u16 = 2;
const M4_NLMSG_DONE: u16 = 3;
const M4_NLMSG_OVERRUN: u16 = 4;
const M4_RTM_NEWLINK: u16 = 16;
const M4_RTM_GETLINK: u16 = 18;
const M4_IFLA_IFNAME: u16 = 3;
const M4_NETLINK_BUFFER_SIZE: usize = 32 * 1024;

#[repr(C)]
pub struct M4IfNameIndex {
    pub if_index: c_uint,
    pub if_name: *mut c_char,
}

#[repr(C)]
struct M4NetlinkHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct M4NetlinkDumpRequest {
    header: M4NetlinkHeader,
    family: u8,
    _padding: [u8; 3],
}

#[repr(C)]
struct M4NetlinkAddress {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
struct M4IfInfoMessage {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: c_int,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct M4RouteAttribute {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
struct M4IfNameMap {
    index: c_uint,
    name_len: u8,
    name: [u8; M4_IF_NAMESIZE],
}

struct M4IfNameMapContext {
    list: *mut M4IfNameMap,
    count: usize,
    capacity: usize,
    string_bytes: usize,
}

#[inline]
unsafe fn m4_if_ioctl_request(fd: c_int, request: u32, ifr: *mut u8) -> i64 {
    sys_ioctl(fd, request, ifr)
}

// Add a single netlink name to the temporary map.  RTM_GETLINK emits one
// IFLA_IFNAME attribute per link, but suppress duplicates defensively because
// the public API promises one entry per interface index.
unsafe fn m4_if_map_add(
    ctx: &mut M4IfNameMapContext,
    index: c_uint,
    name: *const u8,
    name_len: usize,
) -> bool {
    if index == 0 || name.is_null() || name_len == 0 || name_len >= M4_IF_NAMESIZE {
        return true;
    }

    let mut i = 0;
    while i < ctx.count {
        let existing = &*ctx.list.add(i);
        if existing.index == index
            && existing.name_len as usize == name_len
            && core::slice::from_raw_parts(existing.name.as_ptr(), name_len)
                == core::slice::from_raw_parts(name, name_len)
        {
            return true;
        }
        i += 1;
    }

    if ctx.count == ctx.capacity {
        let next_capacity = if ctx.capacity == 0 {
            8
        } else {
            match ctx.capacity.checked_mul(2) {
                Some(value) => value,
                None => {
                    ERRNO = ENOBUFS_VAL;
                    return false;
                }
            }
        };
        let bytes = match next_capacity.checked_mul(core::mem::size_of::<M4IfNameMap>()) {
            Some(value) => value,
            None => {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
        };
        let next = realloc(ctx.list as *mut c_void, bytes) as *mut M4IfNameMap;
        if next.is_null() {
            return false;
        }
        ctx.list = next;
        ctx.capacity = next_capacity;
    }

    let map = &mut *ctx.list.add(ctx.count);
    map.index = index;
    map.name_len = name_len as u8;
    core::ptr::copy_nonoverlapping(name, map.name.as_mut_ptr(), name_len);
    let string_bytes = match name_len.checked_add(1) {
        Some(value) => value,
        None => {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
    };
    ctx.string_bytes = match ctx.string_bytes.checked_add(string_bytes) {
        Some(value) => value,
        None => {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
    };
    ctx.count += 1;
    true
}

// Parse one RTM_NEWLINK message.  A malformed kernel message is treated as a
// failed enumeration rather than allowing an unchecked attribute length to
// escape the receive buffer.
unsafe fn m4_if_parse_link(
    message: *const u8,
    message_len: usize,
    ctx: &mut M4IfNameMapContext,
) -> bool {
    if message_len < core::mem::size_of::<M4NetlinkHeader>() + core::mem::size_of::<M4IfInfoMessage>() {
        ERRNO = ENOBUFS_VAL;
        return false;
    }
    let info = core::ptr::read_unaligned(
        message.add(core::mem::size_of::<M4NetlinkHeader>()) as *const M4IfInfoMessage,
    );
    if info.ifi_index <= 0 {
        return true;
    }

    let mut offset = core::mem::size_of::<M4NetlinkHeader>()
        + core::mem::size_of::<M4IfInfoMessage>();
    while offset < message_len {
        if message_len - offset < core::mem::size_of::<M4RouteAttribute>() {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        let attribute = core::ptr::read_unaligned(
            message.add(offset) as *const M4RouteAttribute,
        );
        let attribute_len = attribute.rta_len as usize;
        if attribute_len < core::mem::size_of::<M4RouteAttribute>()
            || attribute_len > message_len - offset
        {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        if attribute.rta_type == M4_IFLA_IFNAME {
            let data = message.add(offset + core::mem::size_of::<M4RouteAttribute>());
            let data_len = attribute_len - core::mem::size_of::<M4RouteAttribute>();
            let mut name_len = data_len;
            let mut j = 0;
            while j < data_len {
                if *data.add(j) == 0 {
                    name_len = j;
                    break;
                }
                j += 1;
            }
            if !m4_if_map_add(ctx, info.ifi_index as c_uint, data, name_len) {
                return false;
            }
        }
        let aligned_len = match attribute_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
        };
        if aligned_len > message_len - offset {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        offset += aligned_len;
    }
    true
}

unsafe fn m4_if_collect_links(ctx: &mut M4IfNameMapContext) -> bool {
    let fd = socket(
        M4_AF_NETLINK,
        M4_SOCK_RAW | M4_SOCK_CLOEXEC,
        M4_NETLINK_ROUTE,
    );
    if fd < 0 {
        return false;
    }

    let request = M4NetlinkDumpRequest {
        header: M4NetlinkHeader {
            nlmsg_len: core::mem::size_of::<M4NetlinkDumpRequest>() as u32,
            nlmsg_type: M4_RTM_GETLINK,
            nlmsg_flags: M4_NLM_F_REQUEST | M4_NLM_F_DUMP,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        family: 0,
        _padding: [0; 3],
    };
    let destination = M4NetlinkAddress {
        nl_family: M4_AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let sent = sys_sendto(
        fd,
        &request as *const M4NetlinkDumpRequest as *const c_void,
        core::mem::size_of::<M4NetlinkDumpRequest>(),
        0,
        &destination as *const M4NetlinkAddress as *const sockaddr,
        core::mem::size_of::<M4NetlinkAddress>() as c_uint,
    );
    if sent < 0 {
        ERRNO = (-sent) as c_int;
        sys_close(fd as i64);
        return false;
    }

    let mut buffer = [0u8; M4_NETLINK_BUFFER_SIZE];
    loop {
        let received = sys_recvfrom(
            fd,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if received <= 0 {
            if received < 0 {
                ERRNO = (-received) as c_int;
            } else {
                ERRNO = EIO_VAL;
            }
            sys_close(fd as i64);
            return false;
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset < received {
            if received - offset < core::mem::size_of::<M4NetlinkHeader>() {
                ERRNO = ENOBUFS_VAL;
                sys_close(fd as i64);
                return false;
            }
            let header = core::ptr::read_unaligned(
                buffer.as_ptr().add(offset) as *const M4NetlinkHeader,
            );
            let message_len = header.nlmsg_len as usize;
            if message_len < core::mem::size_of::<M4NetlinkHeader>()
                || message_len > received - offset
            {
                ERRNO = ENOBUFS_VAL;
                sys_close(fd as i64);
                return false;
            }
            match header.nlmsg_type {
                M4_NLMSG_DONE => {
                    sys_close(fd as i64);
                    return true;
                }
                M4_NLMSG_ERROR => {
                    if message_len >= core::mem::size_of::<M4NetlinkHeader>() + 4 {
                        let error = core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset + core::mem::size_of::<M4NetlinkHeader>())
                                as *const c_int,
                        );
                        if error != 0 {
                            ERRNO = if error < 0 { -error } else { error };
                        } else {
                            ERRNO = EIO_VAL;
                        }
                    } else {
                        ERRNO = ENOBUFS_VAL;
                    }
                    sys_close(fd as i64);
                    return false;
                }
                M4_NLMSG_NOOP => {}
                M4_NLMSG_OVERRUN => {
                    ERRNO = ENOBUFS_VAL;
                    sys_close(fd as i64);
                    return false;
                }
                M4_RTM_NEWLINK => {
                    if !m4_if_parse_link(
                        buffer.as_ptr().add(offset),
                        message_len,
                        ctx,
                    ) {
                        sys_close(fd as i64);
                        return false;
                    }
                }
                _ => {}
            }
            let aligned_len = match message_len.checked_add(3) {
                Some(value) => value & !3,
                None => {
                    ERRNO = ENOBUFS_VAL;
                    sys_close(fd as i64);
                    return false;
                }
            };
            if aligned_len > received - offset {
                ERRNO = ENOBUFS_VAL;
                sys_close(fd as i64);
                return false;
            }
            offset += aligned_len;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn if_nametoindex(name: *const c_char) -> c_uint {
    if name.is_null() {
        ERRNO = EFAULT_VAL;
        return 0;
    }
    let fd = socket(AF_UNIX, SOCK_DGRAM | M4_SOCK_CLOEXEC, 0);
    if fd < 0 {
        return 0;
    }
    let mut ifr = [0u8; M4_IFREQ_SIZE];
    let mut i = 0;
    while i < M4_IF_NAMESIZE {
        let byte = *name.add(i) as u8;
        ifr[i] = byte;
        i += 1;
        if byte == 0 {
            break;
        }
    }
    let result = m4_if_ioctl_request(fd, M4_SIOCGIFINDEX, ifr.as_mut_ptr());
    sys_close(fd as i64);
    if result < 0 {
        ERRNO = (-result) as c_int;
        return 0;
    }
    core::ptr::read_unaligned(ifr.as_ptr().add(M4_IFR_INDEX_OFFSET) as *const c_uint)
}

#[no_mangle]
pub unsafe extern "C" fn if_indextoname(index: c_uint, name: *mut c_char) -> *mut c_char {
    if name.is_null() {
        ERRNO = EFAULT_VAL;
        return core::ptr::null_mut();
    }
    let fd = socket(AF_UNIX, SOCK_DGRAM | M4_SOCK_CLOEXEC, 0);
    if fd < 0 {
        return core::ptr::null_mut();
    }
    let mut ifr = [0u8; M4_IFREQ_SIZE];
    core::ptr::write_unaligned(
        ifr.as_mut_ptr().add(M4_IFR_INDEX_OFFSET) as *mut c_uint,
        index,
    );
    let result = m4_if_ioctl_request(fd, M4_SIOCGIFNAME, ifr.as_mut_ptr());
    sys_close(fd as i64);
    if result < 0 {
        ERRNO = (-result) as c_int;
        if ERRNO == ENODEV_VAL {
            ERRNO = ENXIO_VAL;
        }
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(
        ifr.as_ptr() as *const c_char,
        name,
        M4_IF_NAMESIZE,
    );
    name
}

#[no_mangle]
pub unsafe extern "C" fn if_nameindex() -> *mut M4IfNameIndex {
    let mut ctx = M4IfNameMapContext {
        list: core::ptr::null_mut(),
        count: 0,
        capacity: 0,
        string_bytes: 0,
    };
    if !m4_if_collect_links(&mut ctx) {
        free(ctx.list as *mut c_void);
        return core::ptr::null_mut();
    }

    let entry_count = match ctx.count.checked_add(1) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            ERRNO = ENOBUFS_VAL;
            return core::ptr::null_mut();
        }
    };
    let entries_bytes = match entry_count.checked_mul(core::mem::size_of::<M4IfNameIndex>()) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            ERRNO = ENOBUFS_VAL;
            return core::ptr::null_mut();
        }
    };
    let total = match entries_bytes.checked_add(ctx.string_bytes) {
        Some(value) => value,
        None => {
            free(ctx.list as *mut c_void);
            ERRNO = ENOBUFS_VAL;
            return core::ptr::null_mut();
        }
    };
    let result = malloc(total) as *mut M4IfNameIndex;
    if result.is_null() {
        free(ctx.list as *mut c_void);
        return core::ptr::null_mut();
    }

    let mut strings = (result as *mut u8).add(entries_bytes);
    let mut i = 0;
    while i < ctx.count {
        let source = &*ctx.list.add(i);
        let destination = result.add(i);
        (*destination).if_index = source.index;
        (*destination).if_name = strings as *mut c_char;
        core::ptr::copy_nonoverlapping(source.name.as_ptr(), strings, source.name_len as usize);
        strings = strings.add(source.name_len as usize);
        *strings = 0;
        strings = strings.add(1);
        i += 1;
    }
    (*result.add(ctx.count)).if_index = 0;
    (*result.add(ctx.count)).if_name = core::ptr::null_mut();
    free(ctx.list as *mut c_void);
    result
}

#[no_mangle]
pub unsafe extern "C" fn if_freenameindex(index: *mut M4IfNameIndex) {
    free(index as *mut c_void);
}

// getifaddrs/freeifaddrs use the same rtnetlink source as if_nameindex, but
// retain link and address records separately.  Every pointer exposed through
// struct ifaddrs points into the allocation for its own node (or into the
// link node for a shared name), so one freeifaddrs walk owns the whole result.

const M4_IFADDRS_HASH_SIZE: usize = 64;
const M4_IFLA_ADDRESS: u16 = 1;
const M4_IFLA_BROADCAST: u16 = 2;
const M4_IFLA_STATS: u16 = 7;
const M4_IFA_ADDRESS: u16 = 1;
const M4_IFA_LOCAL: u16 = 2;
const M4_IFA_LABEL: u16 = 3;
const M4_IFA_BROADCAST: u16 = 4;
const M4_RTM_NEWADDR: u16 = 20;
const M4_RTM_GETADDR: u16 = 22;
const M4_AF_INET: u8 = 2;
const M4_AF_INET6: u8 = 10;
const M4_AF_PACKET: u16 = 17;

#[repr(C)]
pub struct M4IfAddrs {
    pub ifa_next: *mut M4IfAddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: M4IfAddrsIfu,
    pub ifa_data: *mut c_void,
}

#[repr(C)]
pub union M4IfAddrsIfu {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}

#[repr(C)]
struct M4IfAddrsStorage {
    ifa: M4IfAddrs,
    hash_next: *mut M4IfAddrsStorage,
    addr: [u8; 36],
    netmask: [u8; 36],
    ifu: [u8; 36],
    index: c_uint,
    name: [c_char; M4_IF_NAMESIZE + 1],
}

#[repr(C)]
struct M4IfAddrMessage {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

struct M4IfAddrsContext {
    first: *mut M4IfAddrs,
    last: *mut M4IfAddrs,
    hash: [*mut M4IfAddrsStorage; M4_IFADDRS_HASH_SIZE],
}

#[inline]
unsafe fn m4_ifaddrs_storage_addr(storage: *mut M4IfAddrsStorage) -> *mut sockaddr {
    (*storage).addr.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn m4_ifaddrs_storage_netmask(storage: *mut M4IfAddrsStorage) -> *mut sockaddr {
    (*storage).netmask.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn m4_ifaddrs_storage_ifu(storage: *mut M4IfAddrsStorage) -> *mut sockaddr {
    (*storage).ifu.as_mut_ptr() as *mut sockaddr
}

#[inline]
unsafe fn m4_ifaddrs_set_family(storage: *mut u8, family: u16) {
    core::ptr::write_unaligned(storage as *mut u16, family);
}

unsafe fn m4_ifaddrs_copy_addr(
    storage: *mut u8,
    family: u8,
    source: *const u8,
    source_len: usize,
    ifindex: u32,
) -> bool {
    if source.is_null() {
        return false;
    }
    match family {
        M4_AF_INET => {
            if source_len < 4 {
                return false;
            }
            core::ptr::write_bytes(storage, 0, 16);
            m4_ifaddrs_set_family(storage, M4_AF_INET as u16);
            core::ptr::copy_nonoverlapping(source, storage.add(4), 4);
            true
        }
        M4_AF_INET6 => {
            if source_len < 16 {
                return false;
            }
            core::ptr::write_bytes(storage, 0, 28);
            m4_ifaddrs_set_family(storage, M4_AF_INET6 as u16);
            core::ptr::copy_nonoverlapping(source, storage.add(8), 16);
            let address = core::slice::from_raw_parts(source, 16);
            let link_local = (address[0] == 0xfe && address[1] & 0xc0 == 0x80)
                || (address[0] == 0xff && address[1] == 0x02);
            if link_local {
                core::ptr::write_unaligned(storage.add(24) as *mut u32, ifindex);
            }
            true
        }
        _ => false,
    }
}

unsafe fn m4_ifaddrs_copy_lladdr(
    storage: *mut u8,
    source: *const u8,
    source_len: usize,
    ifindex: i32,
    hatype: u16,
) -> bool {
    if source.is_null() || source_len > 24 {
        return false;
    }
    core::ptr::write_bytes(storage, 0, 36);
    m4_ifaddrs_set_family(storage, M4_AF_PACKET);
    core::ptr::write_unaligned(storage.add(4) as *mut i32, ifindex);
    core::ptr::write_unaligned(storage.add(8) as *mut u16, hatype);
    *storage.add(11) = source_len as u8;
    core::ptr::copy_nonoverlapping(source, storage.add(12), source_len);
    true
}

unsafe fn m4_ifaddrs_copy_netmask(
    storage: *mut u8,
    family: u8,
    prefix_len: u8,
) -> bool {
    let mut address = [0u8; 16];
    let bits = if family == M4_AF_INET { 32 } else if family == M4_AF_INET6 { 128 } else { return false };
    let prefix_len = (prefix_len as usize).min(bits);
    let full_bytes = prefix_len / 8;
    let partial_bits = prefix_len % 8;
    let mut i = 0;
    while i < full_bytes {
        address[i] = 0xff;
        i += 1;
    }
    if partial_bits != 0 {
        address[full_bytes] = 0xff << (8 - partial_bits);
    }
    m4_ifaddrs_copy_addr(storage, family, address.as_ptr(), if family == M4_AF_INET { 4 } else { 16 }, 0)
}

unsafe fn m4_ifaddrs_find(
    ctx: &mut M4IfAddrsContext,
    index: u32,
) -> *mut M4IfAddrsStorage {
    let mut current = ctx.hash[(index as usize) % M4_IFADDRS_HASH_SIZE];
    while !current.is_null() {
        if (*current).index == index {
            return current;
        }
        current = (*current).hash_next;
    }
    core::ptr::null_mut()
}

unsafe fn m4_ifaddrs_append(ctx: &mut M4IfAddrsContext, storage: *mut M4IfAddrsStorage) {
    (*storage).ifa.ifa_next = core::ptr::null_mut();
    if ctx.first.is_null() {
        ctx.first = &mut (*storage).ifa;
    } else {
        (*ctx.last).ifa_next = &mut (*storage).ifa;
    }
    ctx.last = &mut (*storage).ifa;
}

unsafe fn m4_ifaddrs_attr_bounds(
    message: *const u8,
    message_len: usize,
    attrs_offset: &mut usize,
) -> bool {
    while *attrs_offset < message_len {
        if message_len - *attrs_offset < core::mem::size_of::<M4RouteAttribute>() {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        let attr = core::ptr::read_unaligned(message.add(*attrs_offset) as *const M4RouteAttribute);
        let attr_len = attr.rta_len as usize;
        if attr_len < core::mem::size_of::<M4RouteAttribute>()
            || attr_len > message_len - *attrs_offset
        {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        let aligned = match attr_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
        };
        if aligned > message_len - *attrs_offset {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        *attrs_offset += aligned;
    }
    true
}

unsafe fn m4_ifaddrs_parse_link(
    message: *const u8,
    message_len: usize,
    ctx: &mut M4IfAddrsContext,
) -> bool {
    let header_len = core::mem::size_of::<M4NetlinkHeader>();
    let info_len = core::mem::size_of::<M4IfInfoMessage>();
    if message_len < header_len + info_len {
        ERRNO = ENOBUFS_VAL;
        return false;
    }
    let info = core::ptr::read_unaligned(message.add(header_len) as *const M4IfInfoMessage);
    if info.ifi_index <= 0 {
        return true;
    }

    let mut attrs = header_len + info_len;
    let attrs_end = message_len;
    let mut stats_len = 0usize;
    while attrs < attrs_end {
        if attrs_end - attrs < core::mem::size_of::<M4RouteAttribute>() {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const M4RouteAttribute);
        let attr_len = attr.rta_len as usize;
        if attr_len < core::mem::size_of::<M4RouteAttribute>() || attr_len > attrs_end - attrs {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        if attr.rta_type == M4_IFLA_STATS {
            stats_len = stats_len.max(attr_len - core::mem::size_of::<M4RouteAttribute>());
        }
        let aligned = match attr_len.checked_add(3) {
            Some(value) => value & !3,
            None => {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
        };
        if aligned > attrs_end - attrs {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
        attrs += aligned;
    }

    let allocation_size = match core::mem::size_of::<M4IfAddrsStorage>().checked_add(stats_len) {
        Some(value) => value,
        None => {
            ERRNO = ENOBUFS_VAL;
            return false;
        }
    };
    let storage = calloc(1, allocation_size) as *mut M4IfAddrsStorage;
    if storage.is_null() {
        return false;
    }
    (*storage).index = info.ifi_index as c_uint;
    (*storage).ifa.ifa_flags = info.ifi_flags;

    attrs = header_len + info_len;
    while attrs < attrs_end {
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const M4RouteAttribute);
        let attr_len = attr.rta_len as usize;
        let data = message.add(attrs + core::mem::size_of::<M4RouteAttribute>());
        let data_len = attr_len - core::mem::size_of::<M4RouteAttribute>();
        match attr.rta_type {
            M4_IFLA_IFNAME => {
                if data_len < (*storage).name.len() {
                    core::ptr::copy_nonoverlapping(
                        data,
                        (*storage).name.as_mut_ptr() as *mut u8,
                        data_len,
                    );
                    if data_len == 0 || *(*storage).name.as_ptr().add(data_len.saturating_sub(1)) != 0 {
                        (*storage).name[data_len] = 0;
                    }
                    (*storage).ifa.ifa_name = (*storage).name.as_mut_ptr();
                }
            }
            M4_IFLA_ADDRESS => {
                let _ = m4_ifaddrs_copy_lladdr(
                    (*storage).addr.as_mut_ptr(),
                    data,
                    data_len,
                    info.ifi_index,
                    info.ifi_type,
                );
                if data_len <= 24 {
                    (*storage).ifa.ifa_addr = m4_ifaddrs_storage_addr(storage);
                }
            }
            M4_IFLA_BROADCAST => {
                let _ = m4_ifaddrs_copy_lladdr(
                    (*storage).ifu.as_mut_ptr(),
                    data,
                    data_len,
                    info.ifi_index,
                    info.ifi_type,
                );
                if data_len <= 24 {
                    (*storage).ifa.ifa_ifu.ifu_broadaddr = m4_ifaddrs_storage_ifu(storage);
                }
            }
            M4_IFLA_STATS => {
                if data_len <= stats_len {
                    (*storage).ifa.ifa_data = (storage as *mut u8).add(core::mem::size_of::<M4IfAddrsStorage>()) as *mut c_void;
                    core::ptr::copy_nonoverlapping(data, (*storage).ifa.ifa_data as *mut u8, data_len);
                }
            }
            _ => {}
        }
        attrs += (attr_len + 3) & !3;
    }

    if (*storage).ifa.ifa_name.is_null() {
        free(storage as *mut c_void);
        return true;
    }
    let bucket = ((*storage).index as usize) % M4_IFADDRS_HASH_SIZE;
    (*storage).hash_next = ctx.hash[bucket];
    ctx.hash[bucket] = storage;
    m4_ifaddrs_append(ctx, storage);
    true
}

unsafe fn m4_ifaddrs_parse_addr(
    message: *const u8,
    message_len: usize,
    ctx: &mut M4IfAddrsContext,
) -> bool {
    let header_len = core::mem::size_of::<M4NetlinkHeader>();
    let addr_len = core::mem::size_of::<M4IfAddrMessage>();
    if message_len < header_len + addr_len {
        ERRNO = ENOBUFS_VAL;
        return false;
    }
    let address = core::ptr::read_unaligned(message.add(header_len) as *const M4IfAddrMessage);
    let link = m4_ifaddrs_find(ctx, address.ifa_index);
    if link.is_null() {
        return true;
    }

    let mut attrs = header_len + addr_len;
    if !m4_ifaddrs_attr_bounds(message, message_len, &mut attrs) {
        return false;
    }
    let allocation_size = core::mem::size_of::<M4IfAddrsStorage>();
    let storage = calloc(1, allocation_size) as *mut M4IfAddrsStorage;
    if storage.is_null() {
        return false;
    }
    (*storage).index = address.ifa_index;
    (*storage).ifa.ifa_name = (*link).ifa.ifa_name;
    (*storage).ifa.ifa_flags = (*link).ifa.ifa_flags;

    attrs = header_len + addr_len;
    while attrs < message_len {
        let attr = core::ptr::read_unaligned(message.add(attrs) as *const M4RouteAttribute);
        let attr_len = attr.rta_len as usize;
        let data = message.add(attrs + core::mem::size_of::<M4RouteAttribute>());
        let data_len = attr_len - core::mem::size_of::<M4RouteAttribute>();
        match attr.rta_type {
            M4_IFA_ADDRESS => {
                let target = if (*storage).ifa.ifa_addr.is_null() {
                    (*storage).addr.as_mut_ptr()
                } else {
                    (*storage).ifu.as_mut_ptr()
                };
                if m4_ifaddrs_copy_addr(target, address.ifa_family, data, data_len, address.ifa_index) {
                    if (*storage).ifa.ifa_addr.is_null() {
                        (*storage).ifa.ifa_addr = m4_ifaddrs_storage_addr(storage);
                    } else {
                        (*storage).ifa.ifa_ifu.ifu_dstaddr = m4_ifaddrs_storage_ifu(storage);
                    }
                }
            }
            M4_IFA_LOCAL => {
                if !(*storage).ifa.ifa_addr.is_null() {
                    core::ptr::copy_nonoverlapping(
                        (*storage).addr.as_ptr(),
                        (*storage).ifu.as_mut_ptr(),
                        36,
                    );
                    (*storage).ifa.ifa_ifu.ifu_dstaddr = m4_ifaddrs_storage_ifu(storage);
                    core::ptr::write_bytes((*storage).addr.as_mut_ptr(), 0, 36);
                    (*storage).ifa.ifa_addr = core::ptr::null_mut();
                }
                if m4_ifaddrs_copy_addr(
                    (*storage).addr.as_mut_ptr(),
                    address.ifa_family,
                    data,
                    data_len,
                    address.ifa_index,
                ) {
                    (*storage).ifa.ifa_addr = m4_ifaddrs_storage_addr(storage);
                }
            }
            M4_IFA_BROADCAST => {
                if m4_ifaddrs_copy_addr(
                    (*storage).ifu.as_mut_ptr(),
                    address.ifa_family,
                    data,
                    data_len,
                    address.ifa_index,
                ) {
                    (*storage).ifa.ifa_ifu.ifu_broadaddr = m4_ifaddrs_storage_ifu(storage);
                }
            }
            M4_IFA_LABEL => {
                if data_len < (*storage).name.len() {
                    core::ptr::copy_nonoverlapping(
                        data,
                        (*storage).name.as_mut_ptr() as *mut u8,
                        data_len,
                    );
                    if data_len == 0 || *(*storage).name.as_ptr().add(data_len.saturating_sub(1)) != 0 {
                        (*storage).name[data_len] = 0;
                    }
                    (*storage).ifa.ifa_name = (*storage).name.as_mut_ptr();
                }
            }
            _ => {}
        }
        attrs += (attr_len + 3) & !3;
    }
    if !(*storage).ifa.ifa_addr.is_null() {
        let _ = m4_ifaddrs_copy_netmask(
            (*storage).netmask.as_mut_ptr(),
            address.ifa_family,
            address.ifa_prefixlen,
        );
        if address.ifa_family == M4_AF_INET || address.ifa_family == M4_AF_INET6 {
            (*storage).ifa.ifa_netmask = m4_ifaddrs_storage_netmask(storage);
        }
    }
    m4_ifaddrs_append(ctx, storage);
    true
}

unsafe fn m4_ifaddrs_dump(
    fd: c_int,
    request_type: u16,
    sequence: u32,
    ctx: &mut M4IfAddrsContext,
) -> bool {
    let request = M4NetlinkDumpRequest {
        header: M4NetlinkHeader {
            nlmsg_len: core::mem::size_of::<M4NetlinkDumpRequest>() as u32,
            nlmsg_type: request_type,
            nlmsg_flags: M4_NLM_F_REQUEST | M4_NLM_F_DUMP,
            nlmsg_seq: sequence,
            nlmsg_pid: 0,
        },
        family: 0,
        _padding: [0; 3],
    };
    let destination = M4NetlinkAddress {
        nl_family: M4_AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let sent = sys_sendto(
        fd,
        &request as *const M4NetlinkDumpRequest as *const c_void,
        core::mem::size_of::<M4NetlinkDumpRequest>(),
        0,
        &destination as *const M4NetlinkAddress as *const sockaddr,
        core::mem::size_of::<M4NetlinkAddress>() as c_uint,
    );
    if sent < 0 {
        ERRNO = (-sent) as c_int;
        return false;
    }

    let mut buffer = [0u8; M4_NETLINK_BUFFER_SIZE];
    loop {
        let received = sys_recvfrom(
            fd,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if received <= 0 {
            if received < 0 {
                ERRNO = (-received) as c_int;
            } else {
                ERRNO = EIO_VAL;
            }
            return false;
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset < received {
            if received - offset < core::mem::size_of::<M4NetlinkHeader>() {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
            let header = core::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const M4NetlinkHeader);
            let message_len = header.nlmsg_len as usize;
            if message_len < core::mem::size_of::<M4NetlinkHeader>() || message_len > received - offset {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
            match header.nlmsg_type {
                M4_NLMSG_DONE => return true,
                M4_NLMSG_ERROR => {
                    if message_len >= core::mem::size_of::<M4NetlinkHeader>() + 4 {
                        let error = core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset + core::mem::size_of::<M4NetlinkHeader>())
                                as *const c_int,
                        );
                        ERRNO = if error < 0 { -error } else if error > 0 { error } else { EIO_VAL };
                    } else {
                        ERRNO = ENOBUFS_VAL;
                    }
                    return false;
                }
                M4_NLMSG_NOOP => {}
                M4_NLMSG_OVERRUN => {
                    ERRNO = ENOBUFS_VAL;
                    return false;
                }
                M4_RTM_NEWLINK if request_type == M4_RTM_GETLINK => {
                    if !m4_ifaddrs_parse_link(buffer.as_ptr().add(offset), message_len, ctx) {
                        return false;
                    }
                }
                M4_RTM_NEWADDR if request_type == M4_RTM_GETADDR => {
                    if !m4_ifaddrs_parse_addr(buffer.as_ptr().add(offset), message_len, ctx) {
                        return false;
                    }
                }
                _ => {}
            }
            let aligned = match message_len.checked_add(3) {
                Some(value) => value & !3,
                None => {
                    ERRNO = ENOBUFS_VAL;
                    return false;
                }
            };
            if aligned > received - offset {
                ERRNO = ENOBUFS_VAL;
                return false;
            }
            offset += aligned;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn freeifaddrs(mut ifp: *mut M4IfAddrs) {
    while !ifp.is_null() {
        let next = (*ifp).ifa_next;
        free(ifp as *mut c_void);
        ifp = next;
    }
}

#[no_mangle]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut M4IfAddrs) -> c_int {
    if ifap.is_null() {
        ERRNO = EFAULT_VAL;
        return -1;
    }
    *ifap = core::ptr::null_mut();
    let mut ctx = M4IfAddrsContext {
        first: core::ptr::null_mut(),
        last: core::ptr::null_mut(),
        hash: [core::ptr::null_mut(); M4_IFADDRS_HASH_SIZE],
    };
    let fd = socket(
        M4_AF_NETLINK,
        M4_SOCK_RAW | M4_SOCK_CLOEXEC,
        M4_NETLINK_ROUTE,
    );
    if fd < 0 {
        return -1;
    }
    if !m4_ifaddrs_dump(fd, M4_RTM_GETLINK, 1, &mut ctx)
        || !m4_ifaddrs_dump(fd, M4_RTM_GETADDR, 2, &mut ctx)
    {
        sys_close(fd as i64);
        freeifaddrs(ctx.first);
        return -1;
    }
    sys_close(fd as i64);
    *ifap = ctx.first;
    0
}

static M4_HERR_UNKNOWN: &[u8] = b"Unknown error\0";
static M4_HERR_HOST_NOT_FOUND: &[u8] = b"Host not found\0";
static M4_HERR_TRY_AGAIN: &[u8] = b"Try again\0";
static M4_HERR_NO_RECOVERY: &[u8] = b"Non-recoverable error\0";
static M4_HERR_NO_DATA: &[u8] = b"Address not available\0";

#[inline]
unsafe fn m4_herror_message(error: c_int) -> *const c_char {
    match error {
        1 => M4_HERR_HOST_NOT_FOUND.as_ptr() as *const c_char,
        2 => M4_HERR_TRY_AGAIN.as_ptr() as *const c_char,
        3 => M4_HERR_NO_RECOVERY.as_ptr() as *const c_char,
        4 => M4_HERR_NO_DATA.as_ptr() as *const c_char,
        _ => M4_HERR_UNKNOWN.as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hstrerror(error: c_int) -> *const c_char {
    m4_herror_message(error)
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
    let _ = fputs(m4_herror_message(h_errno), stderr);
    let _ = fputc(b'\n' as c_int, stderr);
}

// These messages are part of the `netdb.h` API even when a caller uses only
// a numeric address and therefore never enters the DNS resolver.
#[no_mangle]
pub unsafe extern "C" fn gai_strerror(error: c_int) -> *const c_char {
    match error {
        -1 => b"Invalid flags\0".as_ptr() as *const c_char,
        -2 => b"Name does not resolve\0".as_ptr() as *const c_char,
        -3 => M4_HERR_TRY_AGAIN.as_ptr() as *const c_char,
        -4 => M4_HERR_NO_RECOVERY.as_ptr() as *const c_char,
        -6 => b"Unrecognized address family or invalid length\0".as_ptr() as *const c_char,
        -7 => b"Unrecognized socket type\0".as_ptr() as *const c_char,
        -8 => b"Unrecognized service\0".as_ptr() as *const c_char,
        -10 => b"Out of memory\0".as_ptr() as *const c_char,
        -11 => b"System error\0".as_ptr() as *const c_char,
        -12 => b"Overflow\0".as_ptr() as *const c_char,
        _ => M4_HERR_UNKNOWN.as_ptr() as *const c_char,
    }
}

// musl's resolver packet parser is intentionally small: it only decodes the
// wire-format fields and walks record boundaries.  Keep the packet bounds
// checks at this boundary so malformed responses cannot make callers read
// outside the received datagram.

const M4_EMSGSIZE: c_int = 90;
const M4_ENODEV: c_int = 19;
const M4_NS_SECT_MAX: c_int = 4;

#[repr(C)]
pub struct M4NsMsg {
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
pub struct M4NsRR {
    pub name: [c_char; 1025],
    pub type_: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: *const u8,
}

#[repr(C)]
pub struct M4NsFlagData {
    pub mask: c_int,
    pub shift: c_int,
}

// This is part of the public nameser.h accessor-macro ABI.  Its layout is
// two 32-bit integers and therefore remains 128 bytes on the supported
// 64-bit targets, matching musl's ns_parse.o object.
#[no_mangle]
pub static _ns_flagdata: [M4NsFlagData; 16] = [
    M4NsFlagData { mask: 0x8000, shift: 15 },
    M4NsFlagData { mask: 0x7800, shift: 11 },
    M4NsFlagData { mask: 0x0400, shift: 10 },
    M4NsFlagData { mask: 0x0200, shift: 9 },
    M4NsFlagData { mask: 0x0100, shift: 8 },
    M4NsFlagData { mask: 0x0080, shift: 7 },
    M4NsFlagData { mask: 0x0040, shift: 6 },
    M4NsFlagData { mask: 0x0020, shift: 5 },
    M4NsFlagData { mask: 0x0010, shift: 4 },
    M4NsFlagData { mask: 0x000f, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
    M4NsFlagData { mask: 0, shift: 0 },
];

#[inline]
unsafe fn m4_ns_set_errno(value: c_int) {
    ERRNO = value;
}

#[inline]
unsafe fn m4_ns_range(base: *const u8, end: *const u8) -> Option<(usize, usize)> {
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
    let (start, eom) = match m4_ns_range(src, end) {
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
    let (start, end) = match m4_ns_range(ptr, eom) {
        Some(range) => range,
        None => {
            m4_ns_set_errno(M4_EMSGSIZE);
            return -1;
        }
    };
    if section < 0 || section >= M4_NS_SECT_MAX || count < 0 {
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }

    let mut p = start;
    while count > 0 {
        let name_len = dn_skipname(p as *const u8, end as *const u8);
        if name_len < 0 {
            m4_ns_set_errno(M4_EMSGSIZE);
            return -1;
        }
        let name_len = name_len as usize;
        if name_len > end - p || end - p - name_len < 4 {
            m4_ns_set_errno(M4_EMSGSIZE);
            return -1;
        }
        p += name_len + 4;
        if section != 0 {
            if end - p < 6 {
                m4_ns_set_errno(M4_EMSGSIZE);
                return -1;
            }
            p += 4;
            let rdlength = ns_get16(p as *const u8) as usize;
            p += 2;
            if rdlength > end - p {
                m4_ns_set_errno(M4_EMSGSIZE);
                return -1;
            }
            p += rdlength;
        }
        count -= 1;
    }

    let consumed = p - start;
    if consumed > c_int::MAX as usize {
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }
    consumed as c_int
}

#[no_mangle]
pub unsafe extern "C" fn ns_initparse(
    msg: *const u8,
    msglen: c_int,
    handle: *mut M4NsMsg,
) -> c_int {
    if handle.is_null() || msg.is_null() || msglen < 12 {
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }
    let msg_end = (msg as usize).checked_add(msglen as usize);
    let msg_end = match msg_end {
        Some(end) => end,
        None => {
            m4_ns_set_errno(M4_EMSGSIZE);
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
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }
    handle._sect = M4_NS_SECT_MAX;
    handle._rrnum = -1;
    handle._msg_ptr = core::ptr::null();
    0
}

#[no_mangle]
pub unsafe extern "C" fn ns_parserr(
    handle: *mut M4NsMsg,
    section: c_int,
    mut rrnum: c_int,
    rr: *mut M4NsRR,
) -> c_int {
    if handle.is_null() || rr.is_null() || section < 0 || section >= M4_NS_SECT_MAX {
        m4_ns_set_errno(M4_ENODEV);
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
        m4_ns_set_errno(M4_ENODEV);
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
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }
    (*rr).type_ = ns_get16(handle._msg_ptr) as u16;
    handle._msg_ptr = handle._msg_ptr.add(2);
    (*rr).rr_class = ns_get16(handle._msg_ptr) as u16;
    handle._msg_ptr = handle._msg_ptr.add(2);
    if section != 0 {
        if (handle._eom as usize).wrapping_sub(handle._msg_ptr as usize) < 6 {
            m4_ns_set_errno(M4_EMSGSIZE);
            return -1;
        }
        (*rr).ttl = ns_get32(handle._msg_ptr) as u32;
        handle._msg_ptr = handle._msg_ptr.add(4);
        (*rr).rdlength = ns_get16(handle._msg_ptr) as u16;
        handle._msg_ptr = handle._msg_ptr.add(2);
        if (*rr).rdlength as usize > (handle._eom as usize).wrapping_sub(handle._msg_ptr as usize) {
            m4_ns_set_errno(M4_EMSGSIZE);
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
        if handle._sect == M4_NS_SECT_MAX {
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
        m4_ns_set_errno(M4_EMSGSIZE);
        return -1;
    }
    let result = dn_expand(msg, eom, src, dst, dstsiz as c_int);
    if result < 0 {
        m4_ns_set_errno(M4_EMSGSIZE);
    }
    result
}
